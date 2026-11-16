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

	"ocliv/internal/authz"
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

// errNoPublication reports an ownership-scoped delete that matched
// nothing. Callers map it to the same non-disclosing 404 they use for
// an unknown route, so "not yours" and "never existed" are
// indistinguishable to the caller.
var errNoPublication = fmt.Errorf("mcp route: no owned publication")

// deletePublicationAtomically removes one publication and retires the
// route's operator approvals in ONE transaction.
//
// The delete and the approval retirement commit together or not at all:
// a route-less publication with surviving approvals would leave
// authority over a route the caller just deleted (a later route reusing
// the id could inherit it, and the operator's listing would claim
// approvals for a gone route), while a caller told "deleted" while the
// cleanup failed would be a fabricated success. Ownership comes from the
// authenticated (tenant, key) pair; false means the row is not this
// caller's, which is a 404, never a disclosure.
func (s *Server) deletePublicationAtomically(tenant, keyID, routeID string) (bool, int, error) {
	var retired int64
	now := time.Now().UTC().Format(time.RFC3339Nano)
	err := withTx(s.db.SQL(), func(tx *sql.Tx) error {
		res, err := tx.Exec(
			`DELETE FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=?`,
			routeID, tenant, keyID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errNoPublication
		}
		if s.authz == nil {
			return nil
		}
		// The route is gone, so its approvals die with it. Scoped to
		// (tenant, route): no other route's approvals are touched.
		ures, err := tx.Exec(
			`UPDATE authz_grants SET status='revoked', updated_at=?
			 WHERE tenant_id=? AND route_id=? AND status<>'revoked'`,
			now, tenant, routeID)
		if err != nil {
			return err
		}
		retired, _ = ures.RowsAffected()
		return nil
	})
	if err != nil {
		if err == errNoPublication {
			return false, 0, nil
		}
		return false, 0, err
	}
	return true, int(retired), nil
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
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/agent/mcp-routes/")
	if !ok || rest == "" {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet {
		if routeID, ok := strings.CutSuffix(rest, "/authz/pending"); ok && validRouteID(routeID) {
			s.serveKeyPublicationAuthzPending(w, tenant, keyID, routeID)
			return
		}
	}
	if r.Method == http.MethodPost {
		if routeID, ok := strings.CutSuffix(rest, "/disable"); ok && validRouteID(routeID) {
			s.serveKeyPublicationDesiredState(w, tenant, keyID, routeID, false)
			return
		}
		if routeID, ok := strings.CutSuffix(rest, "/enable"); ok && validRouteID(routeID) {
			s.serveKeyPublicationDesiredState(w, tenant, keyID, routeID, true)
			return
		}
		if idx := strings.Index(rest, "/authz/approve/"); idx > 0 {
			routeID := rest[:idx]
			clientID := rest[idx+len("/authz/approve/"):]
			if validRouteID(routeID) && clientID != "" && !strings.Contains(clientID, "/") {
				s.serveKeyPublicationAuthzApprove(w, tenant, keyID, routeID, clientID)
				return
			}
		}
	}
	routeID := rest
	if !validRouteID(routeID) || strings.Contains(routeID, "/") {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet {
		s.serveKeyPublication(w, tenant, keyID, routeID)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	deleted, retired, err := s.deletePublicationAtomically(tenant, keyID, routeID)
	if err != nil {
		// The transaction rolled back both halves: the publication is
		// still there and the caller is told it failed, never a
		// partial success.
		s.db.AuditKey("agent", tenant, keyID, "", "mcp-route-delete", "error",
			"route "+routeID+" delete failed: "+errShort(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !deleted {
		// No row matched this (route, tenant, key) triple. The relay
		// deliberately does not disclose whether the route exists under
		// another owner, so "already gone" and "not owned" share the
		// same non-committal 404. The audit row records the authenticated
		// key and the denied outcome for incident review without leaking
		// publication existence to the caller.
		s.db.AuditKey("agent", tenant, keyID, "", "mcp-route-delete", "denied",
			"route "+routeID+" not found or not owned by this key")
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	// The route is gone, so its approvals died with it in the same
	// transaction: an operator approval is authority over a route that
	// no longer exists, and a later route reusing the id must not
	// inherit it. The retirement is scoped to (tenant, route), so no
	// other route is touched.
	if retired > 0 {
		s.db.Audit("system", tenant, "", "authz-revoke", "ok",
			"revoked "+itoa(uint64(retired))+" approval(s) for removed route "+routeID)
	}
	s.db.AuditKey("agent", tenant, keyID, "", "mcp-route-delete", "ok", "route "+routeID+" removed")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type agentPublicationView struct {
	RouteID          string  `json:"route_id"`
	Host             string  `json:"external_host,omitempty"`
	URL              *string `json:"url"`
	Profile          string  `json:"profile,omitempty"`
	Name             string  `json:"pub_name,omitempty"`
	LeaseID          *string `json:"lease_id"`
	CreatedAt        string  `json:"created_at,omitempty"`
	RevokedAt        *string `json:"revoked_at"`
	VerifiedAt       *string `json:"verified_at"`
	PublicationState string  `json:"publication_state"`
	DesiredEnabled   bool    `json:"desired_enabled"`
	StateGeneration  int64   `json:"state_generation"`
	LeaseState       *string `json:"lease_state"`
	SessionLive      bool    `json:"session_live"`
	HostBinding      string  `json:"host_binding"`
	Admission        string  `json:"admission"`
	AdmissionReason  string  `json:"admission_reason"`
}

// enrichAgentPublication reports current route admission without invoking
// resolveMCPRouteID, which can expire leases and evict sessions. This is a
// side-effect-free diagnostic path available only after signed key auth.
func (s *Server) enrichAgentPublication(tenant, keyID string, p *agentPublicationView) error {
	if p.RevokedAt != nil {
		p.PublicationState = "REVOKED"
	} else if !p.DesiredEnabled {
		p.PublicationState = "DISABLED"
	} else if p.VerifiedAt == nil {
		p.PublicationState = "PENDING"
	} else {
		p.PublicationState = "VERIFIED"
	}
	if s.mcpHost == "" {
		p.HostBinding = "UNKNOWN"
	} else if p.Host != s.mcpHost {
		p.HostBinding = "MISMATCH"
	} else {
		p.HostBinding = "VALID"
		u := s.mcpBaseURL() + "/r/" + p.RouteID + "/mcp"
		p.URL = &u
	}

	reason := "READY"
	switch {
	case p.RevokedAt != nil:
		reason = "PUBLICATION_REVOKED"
	case !p.DesiredEnabled:
		reason = "PUBLICATION_DISABLED"
	case p.HostBinding == "MISMATCH":
		reason = "HOST_MISMATCH"
	case p.HostBinding != "VALID":
		reason = "HOST_MISMATCH"
	case p.LeaseID == nil || *p.LeaseID == "":
		reason = "PUBLICATION_UNBOUND"
	}

	var leaseStatus, leaseMode, leaseTenant, leaseKey string
	var generation uint64
	var expiresAt sql.NullString
	leaseExists := false
	if p.LeaseID != nil && *p.LeaseID != "" {
		err := s.db.SQL().QueryRow(
			`SELECT status, access_mode, tenant_id, agent_key_id, generation, expires_at FROM leases WHERE id=?`,
			*p.LeaseID,
		).Scan(&leaseStatus, &leaseMode, &leaseTenant, &leaseKey, &generation, &expiresAt)
		switch {
		case err == nil:
			leaseExists = true
			p.LeaseState = &leaseStatus
			if session, live := s.liveSession(*p.LeaseID); live && session.Generation == generation {
				p.SessionLive = true
			}
		case err == sql.ErrNoRows:
			missing := "MISSING"
			p.LeaseState = &missing
		default:
			return err
		}
	}

	profile, profileOK := parseIngressProfile(p.Profile)
	switch {
	case reason != "READY":
		// The earlier identity, tombstone, binding, and host checks are
		// authoritative and must not be overwritten by lease details.
	case !profileOK || profile == IngressInvalid:
		reason = "PROFILE_MISMATCH"
	case !leaseExists:
		reason = "LEASE_MISSING"
	case leaseTenant != tenant || leaseKey != keyID:
		reason = "LEASE_OWNERSHIP_MISMATCH"
	case !mcpModeBinding(profile, leaseMode):
		reason = "PROFILE_MISMATCH"
	case leaseStatus == lease.StateExpired:
		reason = "LEASE_EXPIRED"
	case expiresAt.Valid:
		expires, err := time.Parse(time.RFC3339Nano, expiresAt.String)
		if err != nil || !expires.After(time.Now().UTC()) {
			reason = "LEASE_EXPIRED"
		}
	}
	if reason == "READY" && leaseStatus != lease.StateActive {
		reason = "LEASE_OFFLINE"
	}
	if reason == "READY" && !p.SessionLive {
		reason = "LEASE_OFFLINE"
	}
	if reason == "READY" && p.VerifiedAt == nil {
		reason = "PENDING_VERIFICATION"
	}
	p.AdmissionReason = reason
	if reason == "READY" {
		p.Admission = "READY"
	} else {
		p.Admission = "BLOCKED"
	}
	return nil
}

func (s *Server) readKeyPublication(tenant, keyID, routeID string) (*agentPublicationView, error) {
	var p agentPublicationView
	var desiredInt int
	p.RouteID = routeID
	err := s.db.SQL().QueryRow(
		`SELECT external_host, profile, pub_name, lease_id, created_at, revoked_at, verified_at, desired_enabled, state_generation
		 FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=?`,
		routeID, tenant, keyID,
	).Scan(&p.Host, &p.Profile, &p.Name, &p.LeaseID, &p.CreatedAt, &p.RevokedAt, &p.VerifiedAt, &desiredInt, &p.StateGeneration)
	p.DesiredEnabled = desiredInt != 0
	if err == sql.ErrNoRows {
		p.PublicationState = "MISSING"
		p.HostBinding = "UNKNOWN"
		p.Admission = "BLOCKED"
		p.AdmissionReason = "PUBLICATION_NOT_FOUND"
		return &p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.enrichAgentPublication(tenant, keyID, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// serveKeyPublication returns one owner's authenticated admission diagnosis.
// Unknown and differently owned IDs share the same PUBLICATION_NOT_FOUND body.
func (s *Server) serveKeyPublication(w http.ResponseWriter, tenant, keyID, routeID string) {
	p, err := s.readKeyPublication(tenant, keyID, routeID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// serveKeyPublications lists every publication owned by one key with
// durable state, live reachability, canonical URL availability, and a
// precise authenticated admission diagnosis.
func (s *Server) serveKeyPublications(w http.ResponseWriter, tenant, keyID string) {
	rows, err := s.db.SQL().Query(
		`SELECT route_id, external_host, profile, pub_name, lease_id, created_at, revoked_at, verified_at, desired_enabled, state_generation FROM mcp_publications WHERE tenant_id=? AND owner_key_id=? ORDER BY created_at`,
		tenant, keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []agentPublicationView{}
	for rows.Next() {
		var p agentPublicationView
		var desiredInt int
		if err := rows.Scan(&p.RouteID, &p.Host, &p.Profile, &p.Name, &p.LeaseID, &p.CreatedAt, &p.RevokedAt, &p.VerifiedAt, &desiredInt, &p.StateGeneration); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		p.DesiredEnabled = desiredInt != 0
		out = append(out, p)
	}
	// Enrich after the cursor is closed: the store allows a single
	// open connection, so a nested lease lookup inside the scan loop
	// would self-deadlock the listing handler.
	rows.Close()
	for i := range out {
		if err := s.enrichAgentPublication(tenant, keyID, &out[i]); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publications": out})
}

// serveKeyPublicationDesiredState atomically updates desired_enabled with a
// monotonic state_generation increment. When disabling, any bound lease is
// closed and its live session is evicted immediately so forwarding ceases
// even before the publisher exits.
func (s *Server) serveKeyPublicationDesiredState(w http.ResponseWriter, tenant, keyID, routeID string, enabled bool) {
	desiredInt := 0
	if enabled {
		desiredInt = 1
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var boundLease sql.NullString
	var stateGen int64
	var notFound, revoked bool
	err := withTx(s.db.SQL(), func(tx *sql.Tx) error {
		var rev *string
		err := tx.QueryRow(
			`SELECT lease_id, revoked_at, state_generation FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=?`,
			routeID, tenant, keyID,
		).Scan(&boundLease, &rev, &stateGen)
		if err == sql.ErrNoRows {
			notFound = true
			return nil
		}
		if err != nil {
			return err
		}
		if rev != nil {
			revoked = true
			return nil
		}
		res, err := tx.Exec(
			`UPDATE mcp_publications SET desired_enabled=?, state_generation=state_generation+1, updated_at=?
			 WHERE route_id=? AND tenant_id=? AND owner_key_id=? AND revoked_at IS NULL AND state_generation=?`,
			desiredInt, now, routeID, tenant, keyID, stateGen,
		)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return fmt.Errorf("concurrent state update")
		}
		stateGen++
		if !enabled && boundLease.Valid && boundLease.String != "" {
			if _, err := tx.Exec(
				`UPDATE leases SET status=?, expires_at=COALESCE(expires_at, ?) WHERE id=? AND tenant_id=? AND agent_key_id=? AND status=?`,
				lease.StateClosed, now, boundLease.String, tenant, keyID, lease.StateActive,
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if notFound {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	if revoked {
		http.Error(w, "publication revoked", http.StatusConflict)
		return
	}
	if !enabled && boundLease.Valid && boundLease.String != "" {
		s.evictLease(boundLease.String)
	}
	action := "mcp-route-disable"
	if enabled {
		action = "mcp-route-enable"
	}
	s.db.AuditKey("agent", tenant, keyID, boundLease.String, action, "ok", "route "+routeID)
	sessionLive := false
	if boundLease.Valid && boundLease.String != "" {
		_, sessionLive = s.liveSession(boundLease.String)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"route_id":         routeID,
		"desired_enabled":  enabled,
		"state_generation": stateGen,
		"session_live":     sessionLive,
	})
}

func (s *Server) serveKeyPublicationAuthzPending(w http.ResponseWriter, tenant, keyID, routeID string) {
	var exists int
	if err := s.db.SQL().QueryRow(
		`SELECT 1 FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=? AND revoked_at IS NULL`,
		routeID, tenant, keyID,
	).Scan(&exists); err != nil {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	type pendingClient struct {
		ClientID     string `json:"client_id"`
		Name         string `json:"name"`
		RedirectURIs string `json:"redirect_uris"`
		Status       string `json:"status"`
		CreatedAt    string `json:"created_at"`
	}
	out := []pendingClient{}
	if s.authz != nil {
		rows, err := s.db.SQL().Query(
			`SELECT c.id, c.name, c.redirect_uris, COALESCE(g.status, 'pending'), c.created_at
			 FROM authz_clients c
			 LEFT JOIN authz_grants g ON g.client_id=c.id AND g.tenant_id=c.tenant_id AND g.route_id=c.route_id
			 WHERE c.tenant_id=? AND c.route_id=? AND c.revoked_at IS NULL
			   AND (g.status IS NULL OR g.status='pending')
			 ORDER BY c.created_at DESC`,
			tenant, routeID,
		)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var p pendingClient
			if err := rows.Scan(&p.ClientID, &p.Name, &p.RedirectURIs, &p.Status, &p.CreatedAt); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			out = append(out, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"route_id":  routeID,
		"tenant_id": tenant,
		"pending":   out,
	})
}

func (s *Server) serveKeyPublicationAuthzApprove(w http.ResponseWriter, tenant, keyID, routeID, clientID string) {
	if s.authz == nil {
		http.Error(w, "managed authz unavailable", http.StatusConflict)
		return
	}
	var exists int
	if err := s.db.SQL().QueryRow(
		`SELECT 1 FROM mcp_publications WHERE route_id=? AND tenant_id=? AND owner_key_id=? AND revoked_at IS NULL`,
		routeID, tenant, keyID,
	).Scan(&exists); err != nil {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	c, err := s.authz.Store().GetClient(clientID)
	if err != nil || c == nil || c.RevokedAt != nil || c.Tenant != tenant || c.Route != routeID {
		http.Error(w, "unknown client", http.StatusNotFound)
		return
	}
	secret, err := authz.MintPairingSecret()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.authz.Store().ApproveGrantWithPairingSecret(clientID, tenant, routeID, secret, authz.DefaultPairingTTL); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.db.AuditKey("agent", tenant, keyID, "", "authz-approve", "ok", "client "+clientID+" route "+routeID)
	writeJSON(w, http.StatusOK, map[string]any{
		"route_id":       routeID,
		"tenant_id":      tenant,
		"client_id":      clientID,
		"pairing_secret": secret,
		"status":         "approved",
	})
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
		RouteID    string  `json:"route_id"`
		Auth       string  `json:"auth"`
		URL        string  `json:"url"`
		LeaseID    string  `json:"lease_id"`
		VerifiedAt *string `json:"verified_at"`
		CreatedAt  string  `json:"created_at"`
		State      string  `json:"state"`
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
		out = append(out, routeInfo{RouteID: id, Auth: profile, URL: url, LeaseID: leaseID,
			VerifiedAt: verified, CreatedAt: created, State: state})
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
		if id, ok := strings.CutSuffix(rest, "/detach"); ok {
			s.serveMCPRouteDetach(w, tenant, keyID, leaseID, id)
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
		switch profile {
		case IngressMCPAnonymousFixture:
			targetMode = AccessModeMCPAnonymousFixture
		case IngressMCPManaged:
			targetMode = AccessModeMCPManaged
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
			var desiredInt int
			err := s.db.SQL().QueryRow(
				`SELECT route_id, lease_id, revoked_at, desired_enabled FROM mcp_publications WHERE tenant_id=? AND owner_key_id=? AND external_host=? AND profile=? AND pub_name=?`,
				tenant, keyID, s.mcpHost, rest, label).Scan(&routeID, &boundLease, &revoked, &desiredInt)
			if err == nil {
				if revoked != nil {
					http.Error(w, "publication revoked; publish under a fresh name", http.StatusConflict)
					return
				}
				if desiredInt == 0 {
					http.Error(w, "publication disabled; enable it before publishing", http.StatusConflict)
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
					//
					// A MANAGED publication keeps its verification across the
					// rebind: there is no upstream discovery to re-verify,
					// so clearing verified_at would strand the route at 404.
					var oldBinding any
					if boundLease.Valid {
						oldBinding = boundLease.String
					}
					res, err := s.db.SQL().Exec(
						`UPDATE mcp_publications SET lease_id=?,
						   verified_at=CASE WHEN profile=? THEN verified_at ELSE NULL END,
						   updated_at=?
						 WHERE route_id=? AND lease_id IS ? AND revoked_at IS NULL
						   AND EXISTS(SELECT 1 FROM leases WHERE id=? AND status='ACTIVE' AND (expires_at IS NULL OR expires_at > ?))`,
						leaseID, ingressProfileManaged, now, routeID, oldBinding, leaseID, now)
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
				writeJSON(w, http.StatusOK, map[string]any{
					"route_id": routeID,
					"url":      s.mcpBaseURL() + "/r/" + routeID + "/mcp",
					"auth":     rest,
					"created":  false,
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
			// Managed routes have no upstream OAuth to verify: the relay
			// is the Authorization Server, so the publication is active as
			// soon as it is created. Every other profile stays pending
			// until the publisher proves upstream discovery and activates.
			var verifiedAt any
			if profile == IngressMCPManaged {
				verifiedAt = now
			}
			res, err := s.db.SQL().Exec(
				`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, target_path, lease_id, created_at, updated_at, verified_at)
				 SELECT ?,?,?,?,?,?,?,?, ?,?, ? WHERE EXISTS(SELECT 1 FROM leases WHERE id=? AND status='ACTIVE')
				 ON CONFLICT(tenant_id, owner_key_id, external_host, profile, pub_name) DO NOTHING`,
				minted, tenant, keyID, s.mcpHost, rest, label, "/mcp", leaseID,
				now, now, verifiedAt, leaseID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if inserted, rowsErr := res.RowsAffected(); rowsErr != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			} else if inserted == 1 {
				s.db.Audit("agent", tenant, leaseID, "mcp-route", "ok", "publication "+minted+" created")
				writeJSON(w, http.StatusOK, map[string]any{
					"route_id": minted,
					"url":      s.mcpBaseURL() + "/r/" + minted + "/mcp",
					"auth":     rest,
					"created":  true,
				})
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
		// Same transaction discipline as the owner-key delete: the
		// publication row and its route's approvals commit together or
		// not at all. The lease-scoped delete keeps the existing
		// ambiguous 404 for a route not bound to this lease.
		if err := withTx(s.db.SQL(), func(tx *sql.Tx) error {
			res, err := tx.Exec(`DELETE FROM mcp_publications WHERE route_id=? AND lease_id=?`, rest, leaseID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errNoPublication
			}
			if s.authz == nil {
				return nil
			}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			if _, err := tx.Exec(
				`UPDATE authz_grants SET status='revoked', updated_at=?
				 WHERE tenant_id=? AND route_id=? AND status<>'revoked'`,
				now, tenant, rest); err != nil {
				return err
			}
			return nil
		}); err != nil {
			if err == errNoPublication {
				http.Error(w, "unknown route", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// The route is gone, so its operator approvals were retired with
		// it in the same transaction.
		s.db.Audit("agent", tenant, leaseID, "mcp-route-delete", "ok", "route "+rest+" removed")
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveMCPRouteDetach releases a failed replacement lease from a durable
// publication without deleting its identity or grants. The expected lease
// predicate is a CAS: a late cleanup cannot detach a newer successful
// publisher that already rebound the route.
func (s *Server) serveMCPRouteDetach(w http.ResponseWriter, tenant, keyID, leaseID, routeID string) {
	if !validRouteID(routeID) {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.SQL().Exec(
		`UPDATE mcp_publications SET lease_id=NULL,
			verified_at=CASE WHEN profile=? THEN verified_at ELSE NULL END,
			updated_at=?
		 WHERE route_id=? AND tenant_id=? AND owner_key_id=? AND lease_id=? AND revoked_at IS NULL`,
		ingressProfileManaged, now, routeID, tenant, keyID, leaseID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n, err := res.RowsAffected(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	} else if n != 1 {
		http.Error(w, "publication binding changed", http.StatusConflict)
		return
	}
	s.db.AuditKey("agent", tenant, keyID, leaseID, "mcp-route-detach", "ok", "failed publication binding detached: "+routeID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "detached", "route_id": routeID})
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
