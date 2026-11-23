// Signed agent management (relay side): lease status, share/rotate/revoke,
// close, and the authentication that guards them.
//
// Every mutation requires key ownership plus a fresh one-time management
// nonce bound to the signature, so a captured request cannot replay
// inside the clock-skew window (P1-07). This layer never touches visitor
// cookies or share secrets except to mint/revoke them at the owning
// agent's explicit request.
package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/access"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

const maxMgmtBodyBytes = 64 * 1024

// verifySignedMgmtBodyAndSig bounded-reads the request body, restores it for
// downstream handlers, and verifies the Ed25519 management signature.
//
// Any request carrying a non-empty body MUST use ocliv-mgmt-v2 (which binds
// sha256(body) into the signature, P0-4). Legacy ocliv-mgmt-v1 is accepted
// only for bodyless requests.
func verifySignedMgmtBodyAndSig(r *http.Request, pub ed25519.PublicKey, key, nonce string, ts time.Time, sig []byte) bool {
	var bodyBytes []byte
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxMgmtBodyBytes+1))
		if err != nil || len(b) > maxMgmtBodyBytes {
			return false
		}
		bodyBytes = b
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	sum := sha256.Sum256(bodyBytes)
	bodyDigest := hex.EncodeToString(sum[:])
	sigVer := strings.TrimSpace(r.Header.Get("X-Ocliv-Sig-Version"))
	if sigVer == "2" {
		if hdrDigest := strings.TrimSpace(r.Header.Get("X-Ocliv-Body-SHA256")); hdrDigest != "" && hdrDigest != bodyDigest {
			return false
		}
		msgV2 := []byte(fmt.Sprintf("ocliv-mgmt-v2\n%s\n%s\n%s\n%d\n%s\n%s",
			key, r.Method, r.URL.Path, ts.Unix(), nonce, bodyDigest))
		return ed25519.Verify(pub, msgV2, sig)
	}
	// Body-bearing mutations must never downgrade to v1 (P0-4).
	if len(bodyBytes) > 0 {
		return false
	}
	msgV1 := []byte(fmt.Sprintf("ocliv-mgmt-v1\n%s\n%s\n%s\n%d\n%s",
		key, r.Method, r.URL.Path, ts.Unix(), nonce))
	return ed25519.Verify(pub, msgV1, sig)
}

// agentLeaseAuth verifies agent ownership of a lease for management calls.
// Every mutation requires key ownership, expiry, revocation, and version
// checks (D04, B09); cross-tenant access is a conflict, never a takeover.
func (s *Server) agentLeaseAuth(r *http.Request, leaseID string) (tenantID, keyID string, auth bool) {
	key := strings.TrimSpace(r.Header.Get("X-Ocliv-Key"))
	tsRaw := strings.TrimSpace(r.Header.Get("X-Ocliv-TS"))
	sigB64 := strings.TrimSpace(r.Header.Get("X-Ocliv-Sig"))
	if key == "" || tsRaw == "" || sigB64 == "" {
		return "", "", false
	}
	ts, err := time.Parse(time.RFC3339Nano, tsRaw)
	if err != nil || time.Since(ts).Abs() > identity.ClockSkewBound {
		return "", "", false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", "", false
	}
	pub, tenant, status, err := s.lookupKey(key)
	if err != nil || !s.identityAdmitted(tenant, status) {
		return "", "", false
	}
	var owner, ownerTenant, st string
	err = s.db.SQL().QueryRow(`SELECT agent_key_id, tenant_id, status FROM leases WHERE id=?`, leaseID).
		Scan(&owner, &ownerTenant, &st)
	if err != nil || owner != key || ownerTenant != tenant {
		return "", "", false
	}
	nonce := strings.TrimSpace(r.Header.Get("X-Ocliv-Nonce"))
	if r.Method != http.MethodGet {
		// Mutations require a fresh one-time nonce bound to the signature:
		// without it, a captured request replays for the whole skew window
		// (P1-07). Read-only status (GET) needs neither nonce nor claim.
		if nonce == "" || len(nonce) > 128 {
			return "", "", false
		}
		if b, err := base64.StdEncoding.DecodeString(nonce); err != nil || len(b) < 12 {
			return "", "", false
		}
	}
	if !verifySignedMgmtBodyAndSig(r, pub, key, nonce, ts, sig) {
		return "", "", false
	}
	// Consume the nonce exactly once. The INSERT is the atomic claim: a
	// concurrent or replayed duplicate fails the primary key and is denied.
	if r.Method != http.MethodGet && !s.consumeMgmtNonce(tenant, leaseID, nonce) {
		return "", "", false
	}
	return tenant, key, true
}

// consumeMgmtNonce records a verified management nonce and reports whether
// this is its first use. Expired rows are swept on each claim so the table
// stays bounded by the skew window plus margin.
func (s *Server) consumeMgmtNonce(tenant, leaseID, nonce string) bool {
	sum := sha256.Sum256([]byte(nonce))
	id := "n:" + hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	exp := now.Add(identity.ClockSkewBound + time.Minute).Format(time.RFC3339Nano)
	if _, err := s.db.SQL().Exec(`DELETE FROM mgmt_replay WHERE expires_at <= ?`, now.Format(time.RFC3339Nano)); err != nil {
		return false
	}
	res, err := s.db.SQL().Exec(`INSERT OR IGNORE INTO mgmt_replay(id, expires_at) VALUES(?, ?)`, id, exp)
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		s.db.Audit("agent", tenant, leaseID, "mgmt_replay", "denied", "mutation replayed")
		return false
	}
	return true
}

// renewLeaseExpiry compare-and-updates only a still-active lease owned by
// the authenticated key and current generation. Expired or revoked leases
// cannot be resurrected by renewal.
func (s *Server) renewLeaseExpiry(leaseID, tenantID, keyID, publicationID string, generation uint64, ttl time.Duration) (time.Time, bool, error) {
	var updated bool
	var expiry time.Time
	err := withTx(s.db.SQL(), func(tx *sql.Tx) error {
		var state, currentExpiry string
		var currentGeneration int64
		err := tx.QueryRow(`SELECT status, generation, expires_at FROM leases WHERE id=? AND tenant_id=? AND agent_key_id=?`, leaseID, tenantID, keyID).
			Scan(&state, &currentGeneration, &currentExpiry)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		parsedExpiry, err := time.Parse(time.RFC3339Nano, currentExpiry)
		if err != nil || state != "ACTIVE" || uint64(currentGeneration) != generation || !parsedExpiry.After(now) {
			return nil
		}
		expiry = now.Add(ttl)
		res, err := tx.Exec(
			`UPDATE leases SET expires_at=? WHERE id=? AND tenant_id=? AND agent_key_id=? AND status='ACTIVE' AND generation=? AND expires_at=? AND (?='none' OR EXISTS(SELECT 1 FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=? AND lease_id=? AND revoked_at IS NULL))`,
			expiry.Format(time.RFC3339Nano), leaseID, tenantID, keyID, generation, currentExpiry, publicationID, publicationID, tenantID, keyID, leaseID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		updated = n == 1
		return nil
	})
	return expiry, updated, err
}

func (s *Server) handleLeaseRenew(w http.ResponseWriter, tenantID, keyID, leaseID, action string, generation int64, state string, expiresAt sql.NullString) {
	parts := strings.Split(action, "/")
	if len(parts) != 4 || parts[0] != "renew" {
		http.Error(w, "usage: renew/<generation>/<ttl-seconds>/<publication-id|none>", http.StatusBadRequest)
		return
	}
	requestedGeneration, gerr := strconv.ParseUint(parts[1], 10, 64)
	ttlSeconds, terr := strconv.ParseInt(parts[2], 10, 64)
	publicationID := parts[3]
	if requestedGeneration == 0 || gerr != nil || requestedGeneration != uint64(generation) || terr != nil || ttlSeconds < 1 || ttlSeconds > maxIntentTTLSeconds {
		s.db.Audit("agent", tenantID, leaseID, "lease-renew", "denied", "invalid generation or ttl")
		http.Error(w, "invalid generation or ttl", http.StatusConflict)
		return
	}
	now := time.Now().UTC()
	if !expiresAt.Valid || state != "ACTIVE" {
		http.Error(w, "lease is not renewable", http.StatusConflict)
		return
	}
	oldExpiry, err := time.Parse(time.RFC3339Nano, expiresAt.String)
	if err != nil || !oldExpiry.After(now) {
		http.Error(w, "lease has expired", http.StatusConflict)
		return
	}
	if sess, ok := s.liveSession(leaseID); !ok || sess.Generation != requestedGeneration {
		s.db.Audit("agent", tenantID, leaseID, "lease-renew", "denied", "session generation is not current")
		http.Error(w, "session generation is not current", http.StatusConflict)
		return
	}
	expiry, updated, err := s.renewLeaseExpiry(leaseID, tenantID, keyID, publicationID, requestedGeneration, time.Duration(ttlSeconds)*time.Second)
	if err != nil {
		s.db.Audit("agent", tenantID, leaseID, "lease-renew", "error", "database update failed")
		http.Error(w, "renewal failed", http.StatusInternalServerError)
		return
	}
	if !updated {
		if publicationID != "none" {
			var exists bool
			if qerr := s.db.SQL().QueryRow(`SELECT EXISTS(SELECT 1 FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=? AND lease_id=? AND revoked_at IS NULL)`, publicationID, tenantID, keyID, leaseID).Scan(&exists); qerr == nil && !exists {
				s.db.Audit("agent", tenantID, leaseID, "lease-renew", "denied", "publication is deleted, revoked, or no longer bound")
				http.Error(w, "publication is deleted, revoked, or no longer bound", http.StatusGone)
				return
			}
		}
		s.db.Audit("agent", tenantID, leaseID, "lease-renew", "denied", "lease is no longer active or current")
		http.Error(w, "lease is no longer active or current", http.StatusConflict)
		return
	}
	expiryText := expiry.Format(time.RFC3339Nano)
	s.db.Audit("agent", tenantID, leaseID, "lease-renew", "ok", expiryText)
	writeJSON(w, http.StatusOK, map[string]string{"lease_expires_at": expiryText})
}

// handleAgentLeases serves key-scoped HTTP lease inventory so an owner can
// authoritatively resolve and revoke remote HTTP leases even if local state
// lost the lease ID. Ownership comes strictly from the signed agent identity.
func (s *Server) handleAgentLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, keyID, ok := s.agentKeyAuth(r)
	if !ok {
		s.db.Audit("agent", "", "", "mgmt_leases", "denied", "auth failed")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rows, err := s.db.SQL().Query(
		`SELECT id, hostname, label, port, access_mode, status, generation, expires_at, COALESCE(persistent, 0)
		 FROM leases WHERE tenant_id=? AND agent_key_id=? ORDER BY created_at DESC`,
		tenant, keyID,
	)
	if err != nil {
		s.db.AuditKey("agent", tenant, keyID, "", "mgmt_leases", "error", "query failed")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type leaseItem struct {
		LeaseID        string `json:"lease_id"`
		Hostname       string `json:"hostname"`
		Label          string `json:"label"`
		Port           int    `json:"port"`
		AccessMode     string `json:"access_mode"`
		Status         string `json:"status"`
		Generation     int64  `json:"generation"`
		Persistent     bool   `json:"persistent,omitempty"`
		URL            string `json:"url"`
		RouteLive      bool   `json:"route_live"`
		RouteAvailable bool   `json:"route_available"`
		ExpiresAt      string `json:"lease_expires_at,omitempty"`
	}
	out := make([]leaseItem, 0)
	now := time.Now().UTC()
	for rows.Next() {
		var it leaseItem
		var exp sql.NullString
		var persistInt int
		if err := rows.Scan(&it.LeaseID, &it.Hostname, &it.Label, &it.Port, &it.AccessMode, &it.Status, &it.Generation, &exp, &persistInt); err != nil {
			s.db.AuditKey("agent", tenant, keyID, "", "mgmt_leases", "error", "row scan failed")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		it.Persistent = persistInt != 0
		it.URL = "https://" + it.Hostname
		if exp.Valid {
			it.ExpiresAt = exp.String
		}
		if sess, live := s.liveSession(it.LeaseID); live && it.Generation >= 0 && sess.Generation == uint64(it.Generation) {
			it.RouteLive = true
		}
		unexpired := !exp.Valid
		if exp.Valid {
			if parsed, perr := time.Parse(time.RFC3339Nano, exp.String); perr == nil && parsed.After(now) {
				unexpired = true
			}
		}
		it.RouteAvailable = it.RouteLive && it.Status == "ACTIVE" && unexpired
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		s.db.AuditKey("agent", tenant, keyID, "", "mgmt_leases", "error", "row iteration failed")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"leases": out})
}

// handleAgentLease serves signed agent management: status, share, rotate,
// revoke, close. Only the owning key may act (D04).
func (s *Server) handleAgentLease(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/agent/lease/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	leaseID, action := parts[0], parts[1]
	tenant, keyID, ok := s.agentLeaseAuth(r, leaseID)
	if !ok {
		s.db.Audit("agent", "", leaseID, "mgmt_"+action, "denied", "auth failed")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var hostname, mode, state string
	var port int
	var gen, tokenGen int64
	var expiresAt sql.NullString
	err := s.db.SQL().QueryRow(
		`SELECT hostname, port, access_mode, status, generation, token_generation, expires_at FROM leases WHERE id=?`,
		leaseID).Scan(&hostname, &port, &mode, &state, &gen, &tokenGen, &expiresAt)
	if err != nil {
		http.Error(w, "unknown lease", http.StatusNotFound)
		return
	}
	if strings.HasPrefix(action, "renew/") {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleLeaseRenew(w, tenant, keyID, leaseID, action, gen, state, expiresAt)
		return
	}
	switch action {
	case "status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Route liveness is part of the authoritative record: a lease row
		// can read ACTIVE while its session is gone (reconnect window or
		// dead agent). The CLI must show attach and routing separately.
		routeLive, liveGen := false, int64(-1)
		if sess, ok := s.liveSession(leaseID); ok && gen >= 0 && sess.Generation == uint64(gen) {
			routeLive, liveGen = true, gen
		}
		expiry := ""
		if expiresAt.Valid {
			expiry = expiresAt.String
		}
		var renewedAt, renewalResult, renewalDetail string
		_ = s.db.SQL().QueryRow(
			`SELECT time, result, detail FROM audit_events WHERE lease_id=? AND category='lease-renew' ORDER BY id DESC LIMIT 1`, leaseID,
		).Scan(&renewedAt, &renewalResult, &renewalDetail)
		if renewalDetail != "" {
			renewalResult += ": " + renewalDetail
		}
		leaseUnexpired := !expiresAt.Valid
		if expiresAt.Valid {
			if parsed, parseErr := time.Parse(time.RFC3339Nano, expiresAt.String); parseErr == nil && parsed.After(time.Now().UTC()) {
				leaseUnexpired = true
			}
		}
		routeAvailable := routeLive && state == "ACTIVE" && leaseUnexpired
		writeJSON(w, http.StatusOK, map[string]any{
			"lease_id": leaseID, "hostname": hostname, "port": port,
			"access_mode": mode, "status": state, "generation": gen,
			"url":        "https://" + hostname,
			"route_live": routeLive, "route_available": routeAvailable, "live_generation": liveGen,
			"lease_expires_at": expiry, "last_renewal_at": renewedAt, "last_renewal_result": renewalResult,
		})
	case "share":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		raw, err := s.issueShareToken(leaseID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.db.Audit("agent", tenant, leaseID, "share", "ok", "single-redeem token issued")
		writeJSON(w, http.StatusOK, map[string]string{
			"share_url": access.ShareLink("https://"+hostname, raw),
		})
	case "rotate":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		raw, err := s.rotateCredentials(leaseID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.db.Audit("agent", tenant, leaseID, "rotate", "ok", "tokens and sessions revoked")
		// Rotation invalidates live streaming connections, not just future
		// logins; the agent resumes automatically (C10).
		s.evictLease(leaseID)
		writeJSON(w, http.StatusOK, map[string]string{"access_token": raw})
	case "access/revoke":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Visitor-only access revocation (P0-6): revokes visitor tokens and
		// browser sessions and increments token_generation, WITHOUT revoking
		// the lease or tombstoning publications.
		if err := s.revokeVisitorCredentials(leaseID); err != nil {
			s.db.Audit("agent", tenant, leaseID, "mgmt_access_revoke", "denied", "visitor revocation not committed")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.db.Audit("agent", tenant, leaseID, "access_revoke", "ok", "visitor tokens and sessions revoked (lease kept active)")
		s.evictLease(leaseID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "access_revoked"})
	case "revoke":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// All four durable effects commit atomically: success is reported
		// only after commit, never on a partial update (qualification P0).
		if err := s.revokeLease(leaseID); err != nil {
			s.db.Audit("agent", tenant, leaseID, "mgmt_revoke", "denied", "revocation not committed")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.db.Audit("agent", tenant, leaseID, "revoke", "ok", "visitor access revoked")
		// Revoked access terminates live streams immediately; there is no
		// grace for explicitly revoked access (C10, F07).
		s.evictLease(leaseID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	case "close":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.closeLeaseDurable(leaseID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.evictLease(leaseID)
		s.db.Audit("agent", tenant, leaseID, "close", "ok", "lease closed by owner")
		writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
	case "mcp-route":
		// Route listing is read-only (GET, no nonce by design). Creation
		// and deletion use the path-suffixed form below so the profile
		// and route ID travel inside the signed path (P1 publish).
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveMCPRouteList(w, leaseID)
	default:
		if rest, ok := strings.CutPrefix(action, "mcp-route/"); ok {
			s.serveMCPRouteMutation(w, r, tenant, keyID, leaseID, rest)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}
}
