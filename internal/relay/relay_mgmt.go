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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/access"
	"ocliv/internal/identity"
)

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
	msg := []byte(fmt.Sprintf("ocliv-mgmt-v1\n%s\n%s\n%s\n%d\n%s", key, r.Method, r.URL.Path, ts.Unix(), nonce))
	if !ed25519.Verify(pub, msg, sig) {
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
	err := s.db.SQL().QueryRow(
		`SELECT hostname, port, access_mode, status, generation, token_generation FROM leases WHERE id=?`,
		leaseID).Scan(&hostname, &port, &mode, &state, &gen, &tokenGen)
	if err != nil {
		http.Error(w, "unknown lease", http.StatusNotFound)
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
		writeJSON(w, http.StatusOK, map[string]any{
			"lease_id": leaseID, "hostname": hostname, "port": port,
			"access_mode": mode, "status": state, "generation": gen,
			"url":        "https://" + hostname,
			"route_live": routeLive, "live_generation": liveGen,
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
