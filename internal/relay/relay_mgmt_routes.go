// MCP route handlers (relay side): list, create-or-rebind, and delete
// the durable path-route publications bound to an owned lease. Called
// only from the signed agent-management adapter after agentLeaseAuth;
// every mutation here is a durable publication operation, never a
// visitor-auth bypass.
//
// A publication is a stable public route identity separate from the
// active tunnel lease (P1-A): the same (tenant, owner key, external
// host, profile, label) republishes the same route_id across
// replacement leases, so ChatGPT keeps one registered URL while the
// publisher reconnects. The relay stays the sole admission authority:
// resolveMCPRouteID always re-checks the bound lease (ACTIVE, live
// session, generation) plus the publication tombstone.
package relay

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ocliv/internal/identity"
	"ocliv/internal/lease"
)

// mcpBaseURL is the single minting point for public route URLs. The
// port is included only when non-default; Host admission matching
// strips ports independently (canonicalHost), so this affects advertised
// URLs only, never who is admitted.
func (s *Server) mcpBaseURL() string {
	if s.mcpPort != 0 && s.mcpPort != 443 {
		return "https://" + s.mcpHost + ":" + strconv.Itoa(s.mcpPort)
	}
	return "https://" + s.mcpHost
}

// agentKeyAuth verifies key identity for key-scoped management calls
// (P0-D): the same header, clock-skew, signature, and one-time-nonce
// discipline as agentLeaseAuth, without lease scoping. Nonce replay is
// global (mgmt_replay PK), so mutations stay exactly-once.
func (s *Server) agentKeyAuth(r *http.Request) (tenantID, keyID string, auth bool) {
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
	nonce := strings.TrimSpace(r.Header.Get("X-Ocliv-Nonce"))
	if r.Method != http.MethodGet {
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
	if r.Method != http.MethodGet && !s.consumeMgmtNonce(tenant, "", nonce) {
		return "", "", false
	}
	return tenant, key, true
}

// handleAgentPublications serves key-scoped publication management
// (P0-D): GET lists every publication owned by the calling key,
// DELETE removes exactly one owned publication by route ID, leaving
// sibling publications on the same lease untouched. Ownership comes
// from the signed identity, never from a client-supplied lease.
func (s *Server) handleAgentPublications(w http.ResponseWriter, r *http.Request) {
	tenant, keyID, ok := s.agentKeyAuth(r)
	if !ok {
		s.db.Audit("agent", "", "", "mgmt_publications", "denied", "auth failed")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/v1/agent/mcp-routes" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveKeyPublications(w, tenant, keyID)
		return
	}
	routeID, ok := strings.CutPrefix(r.URL.Path, "/v1/agent/mcp-routes/")
	if !ok || !validRouteID(routeID) || strings.Contains(routeID, "/") {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	res, err := s.db.SQL().Exec(
		`DELETE FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=?`,
		routeID, tenant, keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	s.db.Audit("agent", tenant, "", "mcp-route-delete", "ok", "route "+routeID+" removed")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// serveKeyPublications lists every publication owned by one key: identity
// first, leases second. A row is a routing hint only.
func (s *Server) serveKeyPublications(w http.ResponseWriter, tenant, keyID string) {
	rows, err := s.db.SQL().Query(
		`SELECT route_id, external_host, profile, pub_name, lease_id, created_at, revoked_at, verified_at FROM mcp_publications WHERE tenant_id=? AND owner_key_id=? ORDER BY created_at`,
		tenant, keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type pub struct {
		RouteID    string  `json:"route_id"`
		Host       string  `json:"external_host"`
		Profile    string  `json:"profile"`
		Name       string  `json:"pub_name"`
		LeaseID    *string `json:"lease_id"`
		CreatedAt  string  `json:"created_at"`
		RevokedAt  *string `json:"revoked_at"`
		VerifiedAt *string `json:"verified_at"`
		// LeaseState is the durable lease row status (ACTIVE, EXPIRED,
		// CLOSED, REVOKED, ...), nil when the row has no lease binding.
		// SessionLive reports whether a live transport session for the
		// current lease generation exists right now. Durable state and
		// reachability are deliberately separate: active ≠ reachable.
		LeaseState  *string `json:"lease_state"`
		SessionLive bool    `json:"session_live"`
	}
	out := []pub{}
	for rows.Next() {
		var p pub
		if err := rows.Scan(&p.RouteID, &p.Host, &p.Profile, &p.Name, &p.LeaseID, &p.CreatedAt, &p.RevokedAt, &p.VerifiedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out = append(out, p)
	}
	// Enrich after the cursor is closed: the store allows a single
	// open connection, so a nested lease lookup inside the scan loop
	// would self-deadlock the listing handler.
	rows.Close()
	for i := range out {
		if out[i].LeaseID == nil {
			continue
		}
		var status string
		var generation uint64
		switch err := s.db.SQL().QueryRow(
			`SELECT status, generation FROM leases WHERE id=?`, *out[i].LeaseID,
		).Scan(&status, &generation); {
		case err == nil:
			out[i].LeaseState = &status
			if sess, live := s.liveSession(*out[i].LeaseID); live && sess.Generation == generation {
				out[i].SessionLive = true
			}
		default:
			unknown := "unknown"
			out[i].LeaseState = &unknown
		}
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publications": out})
}

// serveMCPRouteList reports the lease's path-route publications
// (P1 `mcp doctor`). URLs are built from the relay's current external
// host: an empty host means route ingress is not configured, and
// listed IDs have no URL. Revoked publications list as revoked so the
// publisher can distinguish tombstones from live bindings.
func (s *Server) serveMCPRouteList(w http.ResponseWriter, leaseID string) {
	rows, err := s.db.SQL().Query(
		`SELECT route_id, profile, created_at, revoked_at, verified_at FROM mcp_publications WHERE lease_id=? ORDER BY created_at`, leaseID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type routeInfo struct {
		RouteID   string `json:"route_id"`
		Auth      string `json:"auth"`
		URL       string `json:"url"`
		CreatedAt string `json:"created_at"`
		State     string `json:"state"`
	}
	out := []routeInfo{}
	for rows.Next() {
		var id, profile, created string
		var revoked, verified *string
		if err := rows.Scan(&id, &profile, &created, &revoked, &verified); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		url := ""
		state := "active"
		if revoked != nil {
			state = "revoked"
		} else if verified == nil {
			state = "pending"
		}
		if s.mcpHost != "" {
			url = s.mcpBaseURL() + "/r/" + id + "/mcp"
		}
		out = append(out, routeInfo{RouteID: id, Auth: profile, URL: url, CreatedAt: created, State: state})
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease_id": leaseID, "routes": out})
}

// serveMCPRouteMutation creates-or-rebinds (POST) and deletes (DELETE)
// one durable publication. Creation is idempotent per (tenant, owner
// key, external host, profile, label): republishing under a replacement
// lease returns the same stable route ID rebound to the new lease
// instead of minting a second route. A revoked publication never
// rebinds: the publisher must publish under a fresh name.
func (s *Server) serveMCPRouteMutation(w http.ResponseWriter, r *http.Request, tenant, keyID, leaseID, rest string) {
	var hostname, label, mode, state, rowTenant, rowKey string
	if err := s.db.SQL().QueryRow(`SELECT hostname, label, access_mode, status, tenant_id, agent_key_id FROM leases WHERE id=?`,
		leaseID).Scan(&hostname, &label, &mode, &state, &rowTenant, &rowKey); err != nil {
		http.Error(w, "unknown lease", http.StatusNotFound)
		return
	}
	if rowTenant != tenant || rowKey != keyID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Activation (P0-A): POST mcp-route/<route-id>/activate marks a
	// pending publication verified after the publisher proves OAuth
	// discovery. Creation and activation are separate precisely so a
	// killed publisher fails closed: the row stays pending and denies
	// tool traffic on every surface until this call succeeds.
	if r.Method == http.MethodPost {
		if id, ok := strings.CutSuffix(rest, "/activate"); ok {
			s.serveMCPRouteActivate(w, tenant, keyID, leaseID, id)
			return
		}
	}
	switch r.Method {
	case http.MethodPost:
		profile, ok := parseIngressProfile(rest)
		if !ok {
			http.Error(w, "unknown ingress profile", http.StatusBadRequest)
			return
		}
		if s.mcpHost == "" {
			http.Error(w, "path-route ingress not configured on this relay", http.StatusConflict)
			return
		}
		if state != lease.StateActive {
			http.Error(w, "lease not active", http.StatusConflict)
			return
		}
		// Modes are born at allocation (P1 `mcp serve --auth`), never
		// flipped in place: changing policy under live streams would
		// either strand the agent (resume denies the mismatch) or
		// silently re-authorize existing streams. Start the tunnel
		// with the matching mode instead.
		targetMode := AccessModeMCPUpstreamOAuth
		if profile == IngressMCPAnonymousFixture {
			targetMode = AccessModeMCPAnonymousFixture
		}
		if mode != targetMode {
			http.Error(w, "lease mode "+mode+" does not support MCP routes; start the tunnel with the matching --auth mode", http.StatusConflict)
			return
		}
		// A publication with the same owner/host/label but a different
		// profile is an explicit-replacement situation, never an
		// implicit downgrade: reject so a caller cannot silently swap
		// the authorization profile under a stable URL (P1-A).
		var clashProfile string
		err := s.db.SQL().QueryRow(
			`SELECT profile FROM mcp_publications WHERE tenant_id=? AND owner_key_id=? AND external_host=? AND pub_name=? AND profile<>?`,
			tenant, keyID, s.mcpHost, label, rest).Scan(&clashProfile)
		if err == nil {
			http.Error(w, "publication exists with profile "+clashProfile+"; delete it first to replace the profile", http.StatusConflict)
			return
		}
		// Test-only barrier (audit P1): a test may revoke the lease
		// here to land exactly in the check-to-insert window and prove
		// the atomic EXISTS predicate denies the mint. Nil in
		// production.
		if s.routeCreateHold != nil {
			s.routeCreateHold()
		}
		// Bounded CAS retry: concurrent publishers racing the same
		// natural key each re-read the winner and retry the atomic
		// rebind. The budget covers the contender fan-in (the 8-way
		// convergence test) with margin; every iteration is a
		// single cheap indexed read plus at most one conditional
		// write, and exhaustion still fails closed below.
		for attempt := 0; attempt < 8; attempt++ {
			var routeID string
			// NULL-safe: revoked tombstones detached by reclaim
			// carry a NULL active binding (P0-B); the revoked
			// check below runs before any binding comparison.
			var boundLease sql.NullString
			var revoked *string
			err := s.db.SQL().QueryRow(
				`SELECT route_id, lease_id, revoked_at FROM mcp_publications WHERE tenant_id=? AND owner_key_id=? AND external_host=? AND profile=? AND pub_name=?`,
				tenant, keyID, s.mcpHost, rest, label).Scan(&routeID, &boundLease, &revoked)
			if err == nil {
				if revoked != nil {
					http.Error(w, "publication revoked; publish under a fresh name", http.StatusConflict)
					return
				}
				if !boundLease.Valid || boundLease.String != leaseID {
					now := time.Now().UTC().Format(time.RFC3339Nano)
					// Atomic authorized rebind: only the expected old
					// binding moves, so a late or concurrent rebind
					// cannot overwrite a newer one — the loser re-reads
					// the winner below (P1-A). The replacement lease is
					// re-proven ACTIVE and within TTL in the same
					// statement, so a close/revoke racing the pre-check
					// cannot bind a dead lease (P0-C).
					oldBinding := boundLease.String
					res, err := s.db.SQL().Exec(
						`UPDATE mcp_publications SET lease_id=?, verified_at=NULL, updated_at=? WHERE route_id=? AND lease_id=? AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM leases WHERE id=? AND status='ACTIVE' AND (expires_at IS NULL OR expires_at > ?))`,
						leaseID, now, routeID, oldBinding, leaseID, now)
					if err != nil {
						http.Error(w, "internal error", http.StatusInternalServerError)
						return
					}
					if n, _ := res.RowsAffected(); n == 1 {
						boundLease = sql.NullString{String: leaseID, Valid: true}
					} else {
						continue
					}
				}
				s.db.Audit("agent", tenant, leaseID, "mcp-route", "ok", "publication "+routeID+" bound")
				writeJSON(w, http.StatusOK, map[string]string{
					"route_id": routeID,
					"url":      s.mcpBaseURL() + "/r/" + routeID + "/mcp",
					"auth":     rest,
				})
				return
			}
			minted, err := MintRouteID()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// The ACTIVE predicate is enforced atomically in the
			// INSERT itself: a close/revoke racing the pre-check
			// above must not mint a row for a dead lease (audit
			// P1). The EXISTS clause and the insert commit as one
			// statement; the natural-key conflict coverges
			// concurrent creates (loser re-reads the winner); a
			// post-revoke attempt inserts zero rows and falls
			// through to the status re-check below.
			now := time.Now().UTC().Format(time.RFC3339Nano)
			// New rows register unverified (P0-A): tool traffic denies
			// until the publisher completes discovery verification
			// and activation. The metadata path stays reachable so
			// that verification can complete.
			_, err = s.db.SQL().Exec(
				`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, target_path, lease_id, created_at, updated_at, verified_at)
				 SELECT ?,?,?,?,?,?,?,?, ?,?, NULL WHERE EXISTS(SELECT 1 FROM leases WHERE id=? AND status='ACTIVE')
				 ON CONFLICT(tenant_id, owner_key_id, external_host, profile, pub_name) DO NOTHING`,
				minted, tenant, keyID, s.mcpHost, rest, label, "/mcp", leaseID,
				now, now, leaseID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			continue
		}
		// No row won: either a transient race (retries exhausted) or
		// the lease died mid-create. Re-read status so a revoke/close
		// racing admission reports 409, not 500.
		var stNow string
		if err := s.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&stNow); err != nil || stNow != lease.StateActive {
			http.Error(w, "lease not active", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
	case http.MethodDelete:
		if !validRouteID(rest) {
			http.Error(w, "unknown route", http.StatusNotFound)
			return
		}
		res, err := s.db.SQL().Exec(`DELETE FROM mcp_publications WHERE route_id=? AND lease_id=?`, rest, leaseID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if n, _ := res.RowsAffected(); n != 1 {
			http.Error(w, "unknown route", http.StatusNotFound)
			return
		}
		s.db.Audit("agent", tenant, leaseID, "mcp-route-delete", "ok", "route "+rest+" removed")
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveMCPRouteActivate marks one pending publication verified. The
// CAS predicate makes activation conditional on the publication still
// being owned, unrevoked, and bound to the calling lease, with that
// lease ACTIVE, unexpired, and owned by the caller: a close, revoke,
// unpublish, expiry, or rebind racing the publisher's verification
// invalidates the stale attempt with 409. An already-verified row
// reports 200 (idempotent replay); a row bound elsewhere, revoked, or
// missing reports 409/404 without revealing which.
func (s *Server) serveMCPRouteActivate(w http.ResponseWriter, tenant, keyID, leaseID, routeID string) {
	if !validRouteID(routeID) {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.SQL().Exec(
		`UPDATE mcp_publications SET verified_at=?, updated_at=? WHERE route_id=? AND tenant_id=? AND owner_key_id=? AND lease_id=? AND revoked_at IS NULL AND verified_at IS NULL AND EXISTS(SELECT 1 FROM leases WHERE id=? AND tenant_id=? AND agent_key_id=? AND status='ACTIVE' AND (expires_at IS NULL OR expires_at > ?))`,
		now, now, routeID, tenant, keyID, leaseID, leaseID, tenant, keyID, now)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 1 {
		s.db.Audit("agent", tenant, leaseID, "mcp-route-activate", "ok", "route "+routeID+" verified")
		writeJSON(w, http.StatusOK, map[string]string{"status": "verified", "route_id": routeID})
		return
	}
	var verified, revoked *string
	var bound sql.NullString
	if err := s.db.SQL().QueryRow(
		`SELECT lease_id, revoked_at, verified_at FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=?`,
		routeID, tenant, keyID).Scan(&bound, &revoked, &verified); err != nil {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	// Idempotent replay only for the lease that holds the verified
	// binding: a superseded lease re-activating after a rebind must
	// still fail, or a stale publisher could mask the new binding.
	if revoked == nil && verified != nil && bound.Valid && bound.String == leaseID {
		writeJSON(w, http.StatusOK, map[string]string{"status": "verified", "route_id": routeID})
		return
	}
	s.db.Audit("agent", tenant, leaseID, "mcp-route-activate", "denied", "stale activation")
	http.Error(w, "publication not activatable", http.StatusConflict)
}
