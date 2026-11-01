// Single-host MCP ingress: path-based routes (/r/<route-id>/mcp) on one
// exact public hostname, for relays without wildcard DNS (P0-A).
//
// A route row is only a routing hint. Admission always re-checks the
// bound lease through admitRoutedLease — TTL expiry, ACTIVE status, live
// session, generation match — the single authority shared with wildcard
// host routing. Routes carry no secrets and can never create a tunnel,
// select an executable, change ports, or bypass ownership.
//
// The mount prefix is stripped only after successful admission, and the
// existing serveRouted path (visitor auth + serveProxied) handles the
// request from there: no proxy or auth implementation is cloned here.
package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/lease"
	"ocliv/internal/metrics"
	"ocliv/internal/store"
)

// Access modes binding a lease to MCP ingress policy (P0-B). They are
// stored in leases.access_mode alongside "protected"/"public" and are
// set only by explicit operator action (P1 `mcp publish --auth`); nothing
// in the tunnel ever silently upgrades a lease into or out of them, and
// resume still denies any mode change (P0-04).
const (
	// AccessModeMCPUpstreamOAuth: Ocliv visitor auth is inapplicable.
	// The application Authorization header is forwarded byte-identical
	// for validation at the upstream MCP resource server, which MUST
	// enforce issuer, audience, scope, expiry, and revocation before
	// tools/call. Ocliv credentials are neither demanded nor consulted.
	AccessModeMCPUpstreamOAuth = "mcp_upstream_oauth"
	// AccessModeMCPAnonymousFixture: no authentication barrier, for an
	// explicitly safe hard-coded read-only demonstration tool with no
	// private data only. Never bind this to a real service.
	AccessModeMCPAnonymousFixture = "mcp_anonymous_fixture"
)

// IsMCPMode reports whether an access mode is an MCP ingress policy
// rather than the generic protected/public contract.
func IsMCPMode(mode string) bool {
	return mode == AccessModeMCPUpstreamOAuth || mode == AccessModeMCPAnonymousFixture
}

// mcpModeBinding enforces the exact route-profile/lease-mode pairing.
// Anything else — an OAuth route to a protected lease, a fixture route
// to an OAuth lease, any route to a public lease — is an unsupported
// deployment combination and admits nothing.
func mcpModeBinding(profile IngressProfile, mode string) bool {
	switch profile {
	case IngressMCPUpstreamOAuth:
		return mode == AccessModeMCPUpstreamOAuth
	case IngressMCPAnonymousFixture:
		return mode == AccessModeMCPAnonymousFixture
	default:
		return false
	}
}

// IngressProfile selects the authorization policy bound to one path
// route. The zero value is invalid by construction: an unparsed profile
// can never admit traffic.
type IngressProfile uint8

const (
	IngressInvalid IngressProfile = iota
	// IngressMCPUpstreamOAuth forwards the request (including the
	// application Authorization header) for validation at the upstream
	// MCP resource server. The relay performs no OAuth itself (P0-B).
	IngressMCPUpstreamOAuth
	// IngressMCPAnonymousFixture serves only an explicitly safe,
	// hard-coded read-only demonstration tool with no private data.
	// Never bind it to a real service (P0-B).
	IngressMCPAnonymousFixture
)

// parseIngressProfile maps the stored profile string to its typed policy.
// Unknown values fail closed: a misconfigured row admits nothing.
func parseIngressProfile(s string) (IngressProfile, bool) {
	switch s {
	case "upstream-oauth":
		return IngressMCPUpstreamOAuth, true
	case "fixture-anonymous":
		return IngressMCPAnonymousFixture, true
	default:
		return IngressInvalid, false
	}
}

// profileString is the inverse of parseIngressProfile for route creation.
func profileString(p IngressProfile) (string, bool) {
	switch p {
	case IngressMCPUpstreamOAuth:
		return "upstream-oauth", true
	case IngressMCPAnonymousFixture:
		return "fixture-anonymous", true
	default:
		return "", false
	}
}

// MCPRoute is the resolved, admitted route: where to forward and under
// which authorization profile. It is built per request from the route
// row plus the live lease admission; it is never persisted as authority.
type MCPRoute struct {
	ExternalHost string
	RouteID      string
	LeaseID      string
	TargetPath   string // fixed "/mcp": the only backend path routes serve
	Profile      IngressProfile
}

// MintRouteID mints an opaque, URL-safe, non-secret routing identifier.
// Non-secret by design: knowledge of an ID alone authorizes nothing;
// the bound lease policy (P0-B) and live admission decide.
func MintRouteID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// validRouteID accepts only short opaque identifiers: 3-64 chars of
// [A-Za-z0-9_-]. Anything else — slashes, dots, percent-escapes left over
// from EscapedPath — is not a route segment.
func validRouteID(id string) bool {
	if len(id) < 3 || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// routePathPrefix is the mount point stripped exactly once, after
// admission. Only the fixed backend path "/mcp" (plus an optional
// trailing slash, normalized away) is servable through a route.
const routePathPrefix = "/r/"

// parseMCPRoutePath matches escaped request paths of the exact shape
// /r/<route-id>/mcp (trailing slash tolerated). The caller must pass
// r.URL.EscapedPath(): encoded separators stay literal text and fail the
// route-ID charset instead of acting as path structure. Deeper paths,
// empty segments, and inner mount prefixes never match.
func parseMCPRoutePath(escapedPath string) (string, bool) {
	rest, ok := strings.CutPrefix(escapedPath, routePathPrefix)
	if !ok {
		return "", false
	}
	return parseRouteRest(rest, true)
}

// mcpWellKnownPrefix is the standards-correct (RFC 9728) placement for
// per-resource discovery: the well-known suffix is inserted after the
// authority, before the resource path. The upstream form is what MCP
// SDKs serve at their own root.
const mcpWellKnownPrefix = "/.well-known/oauth-protected-resource/r/"

// mcpWellKnownUpstreamPath is the only backend path a discovery request
// forwards to: the server-root well-known form, rewritten from the
// route-scoped public shape after admission.
const mcpWellKnownUpstreamPath = "/.well-known/oauth-protected-resource/mcp"

// parseMCPRouteMetadataPath matches escaped request paths of the exact
// shape /.well-known/oauth-protected-resource/r/<route-id>/mcp (no
// trailing slash: discovery URLs are exact). Same EscapedPath and
// charset discipline as parseMCPRoutePath.
func parseMCPRouteMetadataPath(escapedPath string) (string, bool) {
	rest, ok := strings.CutPrefix(escapedPath, mcpWellKnownPrefix)
	if !ok {
		return "", false
	}
	return parseRouteRest(rest, false)
}

// parseRouteRest validates the <route-id>/mcp tail shared by both public
// route shapes. allowSlash tolerates the /mcp trailing slash on tool
// routes only; discovery URLs stay exact.
func parseRouteRest(rest string, allowSlash bool) (string, bool) {
	seg, after, ok := strings.Cut(rest, "/")
	if !ok {
		return "", false
	}
	if !validRouteID(seg) {
		return "", false
	}
	if after != "mcp" && !(allowSlash && after == "mcp/") {
		return "", false
	}
	return seg, true
}

// createMCPRoute binds a route ID to a live lease for the exact external
// host. It validates everything the resolver trusts: host canonicity,
// route-ID charset, known profile, existing lease (via foreign key).
// Mode/profile compatibility is enforced at admission (P0-B), not here,
// so this stays a dumb mapping write.
func createMCPRoute(db *store.DB, externalHost, routeID, leaseID, profile string) error {
	if canonicalHost(externalHost) != externalHost || externalHost == "" {
		return errInvalidRoute("external host must be an exact canonical hostname")
	}
	if strings.Contains(externalHost, ":") {
		return errInvalidRoute("external host must not carry a port")
	}
	if !validRouteID(routeID) {
		return errInvalidRoute("invalid route id")
	}
	if leaseID == "" {
		return errInvalidRoute("lease id required")
	}
	if _, ok := parseIngressProfile(profile); !ok {
		return errInvalidRoute("unknown ingress profile")
	}
	_, err := db.SQL().Exec(
		`INSERT INTO mcp_routes(route_id, lease_id, external_host, profile, target_path, created_at)
		 VALUES(?,?,?,?,?,?)`,
		routeID, leaseID, externalHost, profile, "/mcp",
		time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// deleteMCPRoute removes a route mapping. Lease and session state are
// untouched: revocation and expiry already deny through admission.
func deleteMCPRoute(db *store.DB, routeID string) error {
	_, err := db.SQL().Exec(`DELETE FROM mcp_routes WHERE route_id=?`, routeID)
	return err
}

type routeError string

func (e routeError) Error() string { return "mcp route: " + string(e) }

func errInvalidRoute(reason string) error { return routeError(reason) }

// admitRoutedLease is the single admission authority shared by wildcard
// host routing and path-route resolution: TTL expiry (with eviction and
// durable marking, matching route()), ACTIVE status, live session, and
// generation match. Neither ingress path duplicates these checks.
func (s *Server) admitRoutedLease(t *routeTarget, state string, expiresAt sql.NullString) (*routeTarget, *Session, int) {
	if expiresAt.Valid {
		exp, err := time.Parse(time.RFC3339Nano, expiresAt.String)
		if err != nil || time.Now().UTC().After(exp) {
			s.evictLease(t.LeaseID)
			_, _ = s.db.SQL().Exec(`UPDATE leases SET status=? WHERE id=?`, lease.StateExpired, t.LeaseID)
			s.db.Audit("visitor", "", t.LeaseID, "route", "denied", "lease ttl expired")
			return nil, nil, http.StatusNotFound
		}
		t.ExpiresAt = exp
	}
	if state != lease.StateActive {
		return nil, nil, http.StatusServiceUnavailable
	}
	sess, live := s.liveSession(t.LeaseID)
	if !live {
		return nil, nil, http.StatusServiceUnavailable
	}
	if sess.Generation != t.Generation {
		metrics.Global.FencingRejects.Add(1)
		return nil, nil, http.StatusServiceUnavailable
	}
	return t, sess, 0
}

// admitPathRoute admits one route-shaped request against the relay's
// configured external host and returns the admitted target plus a copy
// of the request with the mount prefix stripped exactly once, aimed at
// the given upstream backend path. It is the only path-route entry
// point: tool routes (/r/<id>/mcp -> /mcp) and discovery routes
// (/.well-known/.../r/<id>/mcp -> server-root well-known form) share
// this binding — host, row, profile/lease-mode match, TTL, ACTIVE
// status, live session, generation — and the same fail-closed mapping
// (unknown/expired -> 404, inactive -> 503). A non-route path returns
// code 0 with nil target, leaving wildcard handling to the caller.
// The caller must guarantee the request arrived on s.mcpHost.
func (s *Server) admitPathRoute(r *http.Request) (*routeTarget, *Session, *http.Request, int) {
	escaped := r.URL.EscapedPath()
	routeID, forwardPath := "", ""
	if id, ok := parseMCPRoutePath(escaped); ok {
		routeID, forwardPath = id, "/mcp"
	} else if id, ok := parseMCPRouteMetadataPath(escaped); ok {
		routeID, forwardPath = id, mcpWellKnownUpstreamPath
	} else {
		return nil, nil, nil, 0
	}
	t, sess, _, code := s.resolveMCPRouteID(routeID)
	if code != 0 {
		// A route-shaped path that cannot be admitted fails closed
		// with path-route semantics. It must never fall through to
		// wildcard routing, the control API, unlock pages, or a
		// default tenant.
		s.db.Audit("visitor", "", "", "route", "denied", "path route inadmissible")
		return nil, nil, nil, code
	}
	r2 := r.Clone(r.Context())
	r2u := *r2.URL
	r2u.Path = forwardPath
	r2u.RawPath = ""
	r2.URL = &r2u
	return t, sess, r2, 0
}

// resolveMCPRouteID admits one parsed path route. The caller guarantees
// the request arrived on s.mcpHost; the row's bound host is re-verified
// here for defense in depth. Unknown IDs, host mismatches, unparseable
// profiles, missing leases, and failed lease admission all fail closed
// with wildcard-identical semantics (404 unknown/expired, 503 inactive).
func (s *Server) resolveMCPRouteID(routeID string) (*routeTarget, *Session, IngressProfile, int) {
	var rowHost, leaseID, profileStr string
	err := s.db.SQL().QueryRow(
		`SELECT external_host, lease_id, profile FROM mcp_routes WHERE route_id=?`,
		routeID).Scan(&rowHost, &leaseID, &profileStr)
	if err != nil {
		return nil, nil, IngressInvalid, http.StatusNotFound
	}
	if rowHost != s.mcpHost {
		s.db.Audit("visitor", "", leaseID, "route", "denied", "route host mismatch")
		return nil, nil, IngressInvalid, http.StatusNotFound
	}
	profile, ok := parseIngressProfile(profileStr)
	if !ok || profile == IngressInvalid {
		s.db.Audit("visitor", "", leaseID, "route", "denied", "unknown route profile")
		return nil, nil, IngressInvalid, http.StatusNotFound
	}
	var t routeTarget
	var state string
	var expiresAt, reconnectUntil sql.NullString
	err = s.db.SQL().QueryRow(
		`SELECT id, label, hostname, port, access_mode, generation, token_generation, status, expires_at, reconnect_until FROM leases WHERE id=?`,
		leaseID).Scan(&t.LeaseID, &t.Label, &t.Hostname, &t.Port, &t.AccessMode, &t.Generation, &t.TokenGen, &state, &expiresAt, &reconnectUntil)
	if err != nil {
		return nil, nil, IngressInvalid, http.StatusNotFound
	}
	if !mcpModeBinding(profile, t.AccessMode) {
		s.db.Audit("visitor", "", leaseID, "route", "denied", "route profile/lease mode mismatch")
		return nil, nil, IngressInvalid, http.StatusNotFound
	}
	t.MCPProfile = profile
	t.ViaPathRoute = true
	admitted, sess, code := s.admitRoutedLease(&t, state, expiresAt)
	if code != 0 {
		return nil, nil, IngressInvalid, code
	}
	return admitted, sess, profile, 0
}
