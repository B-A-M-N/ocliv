// Public ingress: exact-Host routing, visitor authorization, HTTP proxying,
// and WebSocket forwarding (relay side).
package relay

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/access"
	"ocliv/internal/lease"
	"ocliv/internal/metrics"
	"ocliv/internal/protocol"
	"ocliv/internal/proxy"
	"ocliv/internal/transport"
)

// routeTarget is the authoritative routing decision for one request (D01).
type routeTarget struct {
	LeaseID    string
	Label      string
	Hostname   string
	Port       int
	AccessMode string
	Generation uint64
	TokenGen   int64
	// ExpiresAt is the lease TTL deadline, zero when the lease has none.
	// Streams admitted before expiry re-check it so TTL also bounds
	// in-flight requests, not just new admissions (R4).
	ExpiresAt time.Time
	// ViaPathRoute marks decisions admitted through single-host path
	// ingress (P0-A) rather than wildcard host routing. MCPProfile is
	// the route's bound authorization policy, enforced by serveRouted
	// (P0-B). Both are zero on the wildcard path.
	MCPProfile   IngressProfile
	ViaPathRoute bool
	// MCPVerified reports that the path-route publication completed
	// OAuth discovery verification and explicit activation (P0-A).
	// Unverified publications deny the tool path but still serve the
	// public discovery document. False on the wildcard path unless
	// proven otherwise by leaseHasPendingPublication.
	MCPVerified bool
}

// leaseHasPendingPublication reports whether the lease carries at
// least one unrevoked, unverified publication. While pending, the
// lease's wildcard tool path denies; activation (or deletion) clears
// the condition. Metadata paths are unaffected.
func (s *Server) leaseHasPendingPublication(leaseID string) bool {
	var n int
	if err := s.db.SQL().QueryRow(
		`SELECT COUNT(*) FROM mcp_publications WHERE lease_id=? AND revoked_at IS NULL AND verified_at IS NULL`,
		leaseID).Scan(&n); err != nil {
		return true
	}
	return n > 0
}

// leaseExpired reports whether a routed lease has passed its TTL.
func leaseExpired(t *routeTarget) bool {
	return !t.ExpiresAt.IsZero() && time.Now().UTC().After(t.ExpiresAt)
}

// route maps an exact Host to exactly one live lease generation. Anything
// else maps to no destination (D01, D03): malformed -> 400/421, unknown or
// offline -> 404/503 with no cross-tenant hint.
func (s *Server) route(hostport string) (*routeTarget, *Session, int) {
	label, ok := lease.SplitHost(hostport, s.namespace)
	if !ok {
		return nil, nil, http.StatusBadRequest
	}
	var t routeTarget
	var state string
	var expiresAt, reconnectUntil sql.NullString
	err := s.db.SQL().QueryRow(
		`SELECT id, label, hostname, port, access_mode, generation, token_generation, status, expires_at, reconnect_until FROM leases WHERE hostname=?`,
		label+"."+s.namespace,
	).Scan(&t.LeaseID, &t.Label, &t.Hostname, &t.Port, &t.AccessMode, &t.Generation, &t.TokenGen, &state, &expiresAt, &reconnectUntil)
	if err != nil {
		return nil, nil, http.StatusNotFound // no hint (D03)
	}
	// TTL expiry, ACTIVE status, live session, and generation match are
	// enforced by the shared admission authority (see
	// relay_mcp_ingress.go); wildcard routing adds only the hostname
	// lookup above.
	return s.admitRoutedLease(&t, state, expiresAt)
}

// handlePublic is the single public ingress point (no second authority).
func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	metrics.Global.HTTPRequests.Add(1)
	metrics.Global.HTTPInflight.Add(1)
	defer metrics.Global.HTTPInflight.Add(-1)

	t, sess, failCode := s.route(r.Host)
	if s.mcpHost != "" && canonicalHost(r.Host) == s.mcpHost {
		// Tool and discovery route shapes share one admission point
		// (admitPathRoute): the mount prefix is stripped exactly once,
		// after admission, and the request is aimed at the matching
		// upstream backend path (/mcp, or the server-root well-known
		// form for discovery).
		if t2, sess2, r2, code := s.admitPathRoute(r); code != 0 || t2 != nil {
			if code != 0 {
				if code == http.StatusServiceUnavailable {
					w.Header().Set("Retry-After", "5")
				}
				http.Error(w, http.StatusText(code), code)
				return
			}
			t, sess, failCode = t2, sess2, 0
			r = r2
		}
		// A non-route path on the external host keeps existing
		// wildcard behavior, which fails closed for that host.
	}
	if failCode != 0 {
		s.db.Audit("visitor", "", "", "route", "denied", "no route")
		if failCode == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "5")
		}
		http.Error(w, http.StatusText(failCode), failCode)
		return
	}
	s.serveRouted(w, r, t, sess)
}

// serveRouted enforces visitor authorization for one admitted route
// target — wildcard or path — and forwards it upstream. It is the only
// place path-routed requests meet the auth policy: handlePublic admits,
// serveRouted authorizes, serveProxied forwards (P0-A/P0-B).
func (s *Server) serveRouted(w http.ResponseWriter, r *http.Request, t *routeTarget, sess *Session) {
	if t.AccessMode == "public" {
		s.serveProxied(w, r, t, sess, true, false)
		return
	}
	// Pending verification (P0-A): a publication that has not completed
	// OAuth discovery verification and activation denies the tool
	// path on every ingress surface — path route and wildcard alike.
	// The discovery document stays servable so the publisher's own
	// verification probe can complete. On the wildcard path there is
	// no publication row in the target, so pending state is re-proven
	// from the lease binding; a lease with no publications at all
	// (mcp serve, no publish) is unaffected. Denial is 404,
	// indistinguishable from an unknown route.
	if IsMCPMode(t.AccessMode) && r.URL.EscapedPath() == "/mcp" {
		verified := t.MCPVerified
		if !t.ViaPathRoute {
			verified = !s.leaseHasPendingPublication(t.LeaseID)
		}
		if !verified {
			s.db.Audit("visitor", "", t.LeaseID, "mcp_path", "denied", "publication unverified")
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	if IsMCPMode(t.AccessMode) && r.URL.EscapedPath() != "/mcp" &&
		r.URL.EscapedPath() != mcpWellKnownUpstreamPath {
		// P0-3: one MCP publication exposes exactly two endpoints: the
		// tool endpoint (/mcp) and the OAuth discovery document the
		// upstream resource server advertises (P0-E). A lease admitted
		// in an MCP mode — via path route or wildcard hostname — must
		// not carry unrelated application paths upstream. Reject here,
		// before any yamux stream is opened; EscapedPath comparison
		// also defeats %2e traversal without decoding
		// attacker-controlled bytes.
		s.db.Audit("visitor", "", t.LeaseID, "mcp_path", "denied", "non-/mcp path on MCP lease")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if IsMCPMode(t.AccessMode) {
		// P0-B scoped exception to the protected-visitor default: Ocliv
		// visitor credentials are neither demanded, validated, nor
		// fallen back to. The application Authorization header (if any)
		// travels untouched for the upstream resource server, which
		// owns issuer/audience/scope/expiry/revocation enforcement;
		// Ocliv's own credential is stripped before forwarding as on
		// every path (C04). Unauthenticated network cost stays bounded
		// by the per-lease budget enforced in serveProxied.
		s.serveProxied(w, r, t, sess, false, false)
		return
	}
	// Protected: authorize BEFORE allocating a stream or dialing (C01).
	headerTok := access.ExtractHeader(r)
	cookieSess := access.ExtractCookie(r)
	authed := false
	viaCookie := false
	if headerTok != "" {
		if s.checkVisitorToken(t, headerTok) {
			authed = true
		}
	} else if cookieSess != "" {
		if s.checkCookieSession(t, cookieSess) {
			authed = true
			viaCookie = true
		}
	}
	if !authed {
		metrics.Global.VisitorAuthFails.Add(1)
		s.db.Audit("visitor", "", t.LeaseID, "visitor_auth", "denied", "no credential")
		w.Header().Set(access.AuthRequiredFlag, "true")
		presentedAny := headerTok != "" || cookieSess != ""
		if presentedAny || wantsJSON(r) {
			// An explicit but invalid credential is a hard 401 (API and
			// browser alike); only a credential-less browser visit is
			// redirected to the unlock page (C05).
			http.Error(w, "visitor authorization required", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, access.UnlockPath, http.StatusFound)
		return
	}
	if viaCookie {
		if err := access.CheckCSRF(r, tunnelOrigin(r), false); err != nil {
			metrics.Global.VisitorAuthFails.Add(1)
			http.Error(w, "CSRF check failed", http.StatusForbidden)
			return
		}
	}
	s.serveProxied(w, r, t, sess, false, viaCookie)
}

func wantsJSON(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	acc := r.Header.Get("Accept")
	return strings.Contains(ct, "application/json") || strings.Contains(acc, "application/json")
}

// checkVisitorToken validates a scoped Bearer [REDACTED] against stored verifiers (C06).
// Rows are fully consumed and closed before the usage counter is updated:
// the single-connection store would self-deadlock otherwise.
func (s *Server) checkVisitorToken(t *routeTarget, presented string) bool {
	sum := sha256.Sum256([]byte(presented))
	verifier := hex.EncodeToString(sum[:])
	rows, err := s.db.SQL().Query(
		`SELECT id, verifier, expires_at, max_uses, uses FROM access_tokens WHERE lease_id=? AND revoked_at IS NULL`, t.LeaseID)
	if err != nil {
		return false // fail closed (F12)
	}
	now := time.Now().UTC()
	matchID := ""
	for rows.Next() {
		var id, v string
		var exp sql.NullString
		var maxUses, uses int
		if err := rows.Scan(&id, &v, &exp, &maxUses, &uses); err != nil {
			continue
		}
		if v != verifier {
			continue
		}
		if exp.Valid {
			et, err := time.Parse(time.RFC3339Nano, exp.String)
			if err != nil || now.After(et) {
				continue
			}
		}
		if maxUses > 0 && uses >= maxUses {
			continue
		}
		matchID = id
		break
	}
	rows.Close()
	if matchID == "" {
		return false
	}
	// Consume atomically: the conditional UPDATE re-checks every
	// authorization condition the SELECT validated — revocation, expiry,
	// and remaining uses — so a revoke or expiry landing between the read
	// and the write cannot be bypassed (C07, qualification P1). A
	// concurrent consumer or revoker wins the row; the loser sees zero
	// affected rows and is denied.
	res, err := s.db.SQL().Exec(
		`UPDATE access_tokens SET uses=uses+1 WHERE id=? AND revoked_at IS NULL
		 AND (expires_at IS NULL OR expires_at > ?) AND (max_uses=0 OR uses<max_uses)`,
		matchID, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1
}

// checkCookieSession validates a host-only session cookie (C05): signature,
// revocation, idle/absolute expiry, and binding to the current token
// generation (rotation revokes sessions, C10).
func (s *Server) checkCookieSession(t *routeTarget, sessionID string) bool {
	verifier := s.visitors.verifier(sessionID)
	var leaseID string
	var tokenGen int64
	var idleExp, absExp string
	var revoked sql.NullString
	err := s.db.SQL().QueryRow(
		`SELECT lease_id, token_generation, idle_expires_at, absolute_expires_at, revoked_at
		 FROM visitor_sessions WHERE session_verifier=?`, verifier,
	).Scan(&leaseID, &tokenGen, &idleExp, &absExp, &revoked)
	if err != nil {
		return false
	}
	if leaseID != t.LeaseID || tokenGen != t.TokenGen {
		return false
	}
	if revoked.Valid {
		return false
	}
	now := time.Now().UTC()
	ie, err := time.Parse(time.RFC3339Nano, idleExp)
	if err != nil || now.After(ie) {
		return false
	}
	ae, err := time.Parse(time.RFC3339Nano, absExp)
	if err != nil || now.After(ae) {
		return false
	}
	// Refresh idle expiry on use. The UPDATE re-asserts every condition
	// the SELECT validated — same lease and token generation, still
	// unrevoked, still within both expiries — so a concurrent revoke,
	// rotation, or expiry cannot be bypassed between the read and the
	// write (qualification P1). Zero affected rows denies this request.
	res, err := s.db.SQL().Exec(
		`UPDATE visitor_sessions SET idle_expires_at=?
		 WHERE session_verifier=? AND revoked_at IS NULL AND lease_id=?
		 AND token_generation=? AND idle_expires_at > ? AND absolute_expires_at > ?`,
		now.Add(access.CookieIdleTTL).Format(time.RFC3339Nano), verifier,
		t.LeaseID, t.TokenGen,
		now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1
}

// admittedSessionCurrent is the dispatch-time fencing predicate (P1-5):
// after opening a stream, the live session must still be the exact
// session admitted for this request — same registry object and same
// generation the admission check authorized. Liveness alone is not
// sufficient: a replacement racing admission leaves a live session that
// this request must not use.
func admittedSessionCurrent(cur, sess *Session, admittedGen uint64) bool {
	if cur == nil || sess == nil {
		return false
	}
	return cur == sess && cur.Generation == admittedGen
}

// serveProxied forwards one authorized request over a fresh yamux stream.
// Admission control (budget) runs before stream creation (G02); every stream
// is bound to one request, one lease, one generation (E02).
func (s *Server) serveProxied(w http.ResponseWriter, r *http.Request, t *routeTarget, sess *Session, isPublic, viaCookie bool) {
	// MCP-profile admission (P1-10): these requests bypass Ocliv visitor
	// authentication, so a dedicated per-(source,lease) rate budget runs
	// before any stream or budget-slot allocation. Uses the trusted-edge
	// client identity (clientIP), never visitor-supplied identity; no
	// application OAuth token is parsed here. Upstream authorization
	// outcomes are opaque bytes to the relay and therefore not observable
	// — only admission rejections are counted, separately from stream
	// capacity (CapacityRejects) and credential failures.
	if IsMCPMode(t.AccessMode) && !s.mcpAdmission.Allow("mcp:"+clientIP(r)+":"+t.LeaseID) {
		metrics.Global.MCPAdmissionRejects.Add(1)
		s.db.Audit("visitor", "", t.LeaseID, "admission", "denied", "mcp ingress rate limit")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if err := proxy.CheckRequestSyntax(r); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := proxy.CheckUpgradeSyntax(r); err != nil {
		http.Error(w, "unsupported upgrade", http.StatusBadRequest)
		return
	}
	isWS := proxy.IsWebSocketUpgrade(r)
	if isWS {
		// MCP profiles authenticate upstream, never at the relay: the
		// Ocliv visitor header must not be demanded here (P0-B).
		if !viaCookie && !isPublic && !IsMCPMode(t.AccessMode) && access.ExtractHeader(r) == "" {
			http.Error(w, "visitor authorization required", http.StatusUnauthorized)
			return
		}
		if err := access.CheckUpgradeOrigin(r, tunnelOrigin(r), !viaCookie); err != nil {
			metrics.Global.VisitorAuthFails.Add(1)
			http.Error(w, "websocket origin rejected", http.StatusForbidden)
			return
		}
	}
	if err := sess.Budget.TryAcquire(isWS); err != nil {
		metrics.Global.CapacityRejects.Add(1)
		s.db.Audit("visitor", "", t.LeaseID, "admission", "denied", "budget exceeded")
		http.Error(w, "capacity exceeded", http.StatusServiceUnavailable)
		return
	}
	defer sess.Budget.Release(isWS)

	if sess.Yamux.IsClosed() {
		http.Error(w, "agent offline", http.StatusServiceUnavailable)
		return
	}
	stream, err := transport.OpenStream(sess.Yamux)
	if err != nil {
		metrics.Global.CapacityRejects.Add(1)
		http.Error(w, "capacity exceeded", http.StatusServiceUnavailable)
		return
	}
	defer stream.Close()

	// Re-check identity at dispatch (P1-5): the live session must still
	// be the admitted one — same object, same generation. A reconnect
	// or replacement racing admission must not route this request's
	// stream to a different agent generation (F13).
	if cur, live := s.liveSession(t.LeaseID); !live || !admittedSessionCurrent(cur, sess, t.Generation) {
		http.Error(w, "agent offline", http.StatusServiceUnavailable)
		return
	}
	// Test-only barrier (P2-1): a test may replace the live session
	// here to land exactly in the check-to-write window. The head
	// below still binds the admitted generation, so the agent-side
	// gate rejects the stale write; nothing here trusts the new
	// session for this request.
	if s.dispatchHold != nil {
		s.dispatchHold()
	}

	reqID := newRequestID()
	head := protocol.RequestHead{
		Type: "request_head", Proto: protocol.Version, RequestID: reqID,
		LeaseID: t.LeaseID, Generation: sess.Generation,
		Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
		Headers:  proxy.SanitizeVisitorHeaders(r.Header),
		RemoteIP: clientIP(r), PubOrigin: tunnelOrigin(r),
		BodyKnown: r.ContentLength >= 0, BodyLen: r.ContentLength,
		UpgradeWS: isWS,
	}
	if cookies := proxy.AppCookies(r); cookies != "" {
		head.Headers["Cookie"] = cookies
	}
	head.Headers["X-Forwarded-Host"] = strings.ToLower(r.Host)
	head.Headers["X-Forwarded-Proto"] = publicScheme(r)
	rawHead, err := protocol.MarshalJSON(head)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := protocol.WriteFrame(stream, protocol.FRequestHead, rawHead); err != nil {
		http.Error(w, "agent unreachable", http.StatusBadGateway)
		return
	}
	if isWS {
		s.serveWebSocket(w, r, stream, reqID, t, sess)
		return
	}
	s.serveHTTP(w, r, stream, reqID, t)
}
