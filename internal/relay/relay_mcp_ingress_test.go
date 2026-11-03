package relay

// Single-host MCP ingress tests (P0-A). A fixed public hostname serves
// path-based routes (/r/<route-id>/mcp) without wildcard DNS. Every test
// below pins a denial or a routing invariant; the only test that admits a
// request uses a live (fabricated) session and asserts the exact forward
// path. None of these tests may disturb wildcard host routing.

import (
	"crypto/ed25519"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"ocliv/internal/lease"
	"ocliv/internal/store"
)

// postMCPRoute POSTs a signed route-create through the full handler
// stack (authority + management auth + mutation), returning the status
// and raw body.
func postMCPRoute(t *testing.T, s *Server, priv ed25519.PrivateKey, keyID, leaseID, profile string) (int, string) {
	t.Helper()
	path := "/v1/agent/lease/" + leaseID + "/mcp-route/" + profile
	r := signedMgmtRequest(t, priv, keyID, http.MethodPost, path)
	r.Host = "relay.example.test"
	r.RequestURI = path
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// postMCPDelete issues a signed route DELETE through the full handler
// stack, returning the status and body.
func postMCPDelete(t *testing.T, s *Server, priv ed25519.PrivateKey, keyID, leaseID, routeID string) (int, string) {
	t.Helper()
	path := "/v1/agent/lease/" + leaseID + "/mcp-route/" + routeID
	r := signedMgmtRequest(t, priv, keyID, http.MethodDelete, path)
	r.Host = "relay.example.test"
	r.RequestURI = path
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// A lease already revoked before creation fails closed with 409 and no
// row: the pre-check denies without touching the mapping table.
func TestCreateRouteAgainstRevokedLeaseFailsClosed(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-dead", "dead.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	if err := s.revokeLease("lse-dead"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	code, _ := postMCPRoute(t, s, priv, "key-test", "lse-dead", "upstream-oauth")
	if code != http.StatusConflict {
		t.Fatalf("create on revoked lease: status=%d, want 409", code)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications WHERE lease_id='lse-dead'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("route row minted for revoked lease: n=%d err=%v", n, err)
	}
}

// A revoke landing between the ACTIVE pre-check and the INSERT must
// not mint a route: the atomic EXISTS predicate denies the write and
// the handler reports 409, not 200 and not 500. The routeCreateHold
// barrier makes the interleaving deterministic; without the EXISTS
// predicate this test goes red (row created, 200 returned).
func TestCreateRouteRevokedMidFlightDenied(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-race", "race.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	fired := make(chan struct{}, 1)
	s.routeCreateHold = func() {
		if err := s.revokeLease("lse-race"); err != nil {
			t.Errorf("hook revoke: %v", err)
		}
		fired <- struct{}{}
	}
	defer func() { s.routeCreateHold = nil }()
	code, _ := postMCPRoute(t, s, priv, "key-test", "lse-race", "upstream-oauth")
	select {
	case <-fired:
	default:
		t.Fatal("create barrier never fired")
	}
	if code != http.StatusConflict {
		t.Fatalf("mid-flight revoke: status=%d, want 409", code)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications WHERE lease_id='lse-race'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("route row minted after mid-flight revoke: n=%d err=%v", n, err)
	}
}

// A revoke of the REPLACEMENT lease landing between the ACTIVE
// pre-check and the rebind UPDATE must not move the binding: the fenced
// rebind denies the write and the handler reports 409, never 200 and
// never a route bound to a dead lease. Without the EXISTS predicate
// this test goes red (binding moves, 200 returned).
func TestRebindRevokedMidFlightDenied(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "fence.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	insertMCPLeaseRow(t, db, "lse-b", "other.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	relabel(t, db, "lse-b", "fence")
	fired := make(chan struct{}, 1)
	s.routeCreateHold = func() {
		if err := s.revokeLease("lse-b"); err != nil {
			t.Errorf("hook revoke: %v", err)
		}
		fired <- struct{}{}
	}
	defer func() { s.routeCreateHold = nil }()
	code, _ := postMCPRoute(t, s, priv, "key-test", "lse-b", "upstream-oauth")
	select {
	case <-fired:
	default:
		t.Fatal("rebind barrier never fired")
	}
	if code != http.StatusConflict {
		t.Fatalf("mid-flight revoke of replacement: status=%d, want 409", code)
	}
	var bound string
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id=?`, r1).Scan(&bound); err != nil || bound != "lse-a" {
		t.Fatalf("binding moved to dead lease: bound=%q err=%v", bound, err)
	}
}

// A close of the REPLACEMENT lease racing the rebind must also fail
// closed with 409, leaving the original binding untouched (P0-C).
func TestRebindClosedMidFlightDenied(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "fence2.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	insertMCPLeaseRow(t, db, "lse-b", "other2.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	relabel(t, db, "lse-b", "fence2")
	fired := make(chan struct{}, 1)
	s.routeCreateHold = func() {
		if err := s.closeLeaseDurable("lse-b"); err != nil {
			t.Errorf("hook close: %v", err)
		}
		fired <- struct{}{}
	}
	defer func() { s.routeCreateHold = nil }()
	code, _ := postMCPRoute(t, s, priv, "key-test", "lse-b", "upstream-oauth")
	select {
	case <-fired:
	default:
		t.Fatal("rebind barrier never fired")
	}
	if code != http.StatusConflict {
		t.Fatalf("mid-flight close of replacement: status=%d, want 409", code)
	}
	var bound string
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id=?`, r1).Scan(&bound); err != nil || bound != "lse-a" {
		t.Fatalf("binding moved to closed lease: bound=%q err=%v", bound, err)
	}
}

// newMCPServer builds a relay with path-route ingress enabled for
// public.example.org. Wildcard namespace and relay authority stay exactly
// as in the other suites.
func newMCPServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{
		DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test",
		MCPExternalHost: "public.example.org",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

// insertMCPLeaseRow creates a directly-bound lease row for route tests.
// Unlike insertLeaseRow it sets an explicit hostname/access mode and TTL.
// The label is the hostname's left label, mirroring named-lease
// allocation: publications key on it, so distinct test leases stay in
// distinct publications unless a test deliberately shares a name.
func insertMCPLeaseRow(t *testing.T, db *store.DB, id, hostname, mode, status string, gen uint64, expiresAt *string) {
	t.Helper()
	var exp any
	if expiresAt != nil {
		exp = *expiresAt
	}
	label := hostname
	if i := strings.Index(hostname, "."); i > 0 {
		label = hostname[:i]
	}
	_, err := db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, expires_at, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		id, "tenant-test", "key-test", hostname, label, 3000, mode, gen, status, exp,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
}

// liveFabricatedSession registers a registry session with a real (idle)
// yamux client so liveSession admits it without network traffic.
func liveFabricatedSession(t *testing.T, s *Server, leaseID string, gen uint64) {
	t.Helper()
	cli, srv := net.Pipe()
	t.Cleanup(func() { _ = cli.Close() })
	t.Cleanup(func() { _ = srv.Close() })
	ys, err := yamux.Client(cli, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	s.registry.mu.Lock()
	s.registry.sessions[leaseID] = &Session{
		LeaseID: leaseID, Generation: gen, Yamux: ys,
		closed: make(chan struct{}),
	}
	s.registry.mu.Unlock()
}

// serveRoute is handlePublic through the full Handler stack (including
// authorizeHost) with an explicit Host.
func serveRoute(s *Server, method, host, path string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestMCPRoutePathParsing(t *testing.T) {
	cases := []struct {
		path string
		id   string
		ok   bool
	}{
		{"/r/abc123/mcp", "abc123", true},
		{"/r/abc123/mcp/", "abc123", true},
		{"/r/ABC-9_x/mcp", "ABC-9_x", true},
		{"/r/abc123/mcp/extra", "", false}, // deeper paths never forward
		{"/r/abc123/mcp/mcp", "", false},   // no double-strip confusion
		{"/r/abc123/other", "", false},
		{"/r//mcp", "", false},
		{"/r/abc123", "", false},
		{"/r/abc123/", "", false},
		{"/mcp", "", false},
		{"/v1/agent/enroll", "", false},
		{"/r/abc/r/xyz/mcp", "", false}, // inner mount prefix is literal
		// EscapedPath input: an encoded slash must stay a literal part
		// of the segment and fail the route-ID charset, never act as a
		// separator.
		{"/r/abc%2fdef/mcp", "", false},
		{"/r/abc%2e%2e/mcp", "", false},
		{"/r/%2e%2e/mcp", "", false},
	}
	for _, c := range cases {
		id, ok := parseMCPRoutePath(c.path)
		if ok != c.ok || id != c.id {
			t.Errorf("parseMCPRoutePath(%q) = (%q, %v), want (%q, %v)",
				c.path, id, ok, c.id, c.ok)
		}
	}
}

func TestMCPRouteMetadataPathParsing(t *testing.T) {
	cases := []struct {
		path string
		id   string
		ok   bool
	}{
		{"/.well-known/oauth-protected-resource/r/abc123/mcp", "abc123", true},
		{"/.well-known/oauth-protected-resource/r/ABC-9_x/mcp", "ABC-9_x", true},
		{"/.well-known/oauth-protected-resource/r/abc123/mcp/", "", false},
		{"/.well-known/oauth-protected-resource/r/abc123/other", "", false},
		{"/.well-known/oauth-protected-resource/r//mcp", "", false},
		{"/.well-known/oauth-protected-resource/r/abc123", "", false},
		{"/.well-known/oauth-protected-resource/mcp", "", false}, // server-root form is not route-scoped
		{"/.well-known/oauth-protected-resource/r/abc%2fdef/mcp", "", false},
		{"/r/abc123/mcp", "", false}, // plain route shape is not metadata
		{"/.well-known/openid-configuration", "", false},
	}
	for _, c := range cases {
		id, ok := parseMCPRouteMetadataPath(c.path)
		if ok != c.ok || id != c.id {
			t.Errorf("parseMCPRouteMetadataPath(%q) = (%q, %v), want (%q, %v)",
				c.path, id, ok, c.id, c.ok)
		}
	}
}

// TestMCPRouteMetadataAdmitted: a live MCP route's discovery document is
// admitted through the same route binding (host, row, generation, lease
// status) and rewritten to the upstream server-root well-known form the
// MCP SDKs serve. No yamux stream is opened by this test: admission and
// path rewriting are asserted, not the tunneled bytes.
func TestMCPRouteMetadataAdmitted(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-md", "md.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	liveFabricatedSession(t, s, "lse-md", 1)
	if err := createMCPRoute(db, "public.example.org", "route-md", "lse-md", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/r/route-md/mcp", nil)
	r.Host = "public.example.org"
	tgt, sess, out, code := s.admitPathRoute(r)
	if code != 0 {
		t.Fatalf("metadata discovery denied: code=%d", code)
	}
	if tgt.LeaseID != "lse-md" || sess == nil || !tgt.ViaPathRoute {
		t.Fatalf("metadata admitted wrong target: %+v", tgt)
	}
	if out.URL.EscapedPath() != "/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("upstream forward path = %q, want server-root well-known form", out.URL.EscapedPath())
	}
	// Unknown route IDs fail closed without reaching the lease.
	r2 := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/r/no-such-route/mcp", nil)
	r2.Host = "public.example.org"
	if _, _, _, code := s.admitPathRoute(r2); code != http.StatusNotFound {
		t.Fatalf("unknown metadata route: got %d, want 404", code)
	}
	// A revoked lease denies discovery exactly like tool traffic.
	insertMCPLeaseRow(t, db, "lse-mdr", "mdr.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateRevoked, 1, nil)
	if err := createMCPRoute(db, "public.example.org", "route-mdr", "lse-mdr", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	r3 := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/r/route-mdr/mcp", nil)
	r3.Host = "public.example.org"
	if _, _, _, code := s.admitPathRoute(r3); code != http.StatusServiceUnavailable {
		t.Fatalf("revoked metadata route: got %d, want 503", code)
	}
}

// TestSharedHostMetadataDiscoveryFullHandler proves the complete
// authority → admission → forwarding sequence for OAuth discovery on a
// shared relay/MCP hostname (audit P0). Before the fix, authorizeHost
// rejected /.well-known/oauth-protected-resource/r/<id>/mcp with 421
// before admission; the tool path /r/<id>/mcp worked, so discovery was
// the only broken half. A live route must forward (the fake agent
// aborts, surfacing 502 — never 421); unknown/revoked/malformed routes
// fail closed with path-route semantics; unrelated .well-known paths
// keep the 421; agent control on the shared authority is untouched.
func TestSharedHostMetadataDiscoveryFullHandler(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{
		DB: db, Namespace: "t.example.test",
		RelayHost: "public.example.org", MCPExternalHost: "public.example.org",
	})
	if err != nil {
		t.Fatal(err)
	}
	insertMCPLeaseRow(t, db, "lse-mdh", "mdh.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	h := newDispatchHarness(t)
	insertRegistrySession(s, &Session{LeaseID: "lse-mdh", Generation: 1, Yamux: h.relayYS,
		Budget: s.budgets.For("lse-mdh"), closed: make(chan struct{})})
	if err := createMCPRoute(db, "public.example.org", "route-mdh", "lse-mdh", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	// Live discovery through the FULL handler: admitted and forwarded,
	// never 421. The fake agent applies the generation contract and
	// aborts, so the visitor sees a 5xx, never success, never 421.
	w := serveRoute(s, http.MethodGet, "public.example.org", "/.well-known/oauth-protected-resource/r/route-mdh/mcp", nil)
	select {
	case head := <-h.gotHead:
		if head.Generation != 1 || head.LeaseID != "lse-mdh" {
			t.Fatalf("discovery forwarded wrong head: %+v", head)
		}
	case <-h.noHead:
		t.Fatal("live discovery never reached the agent")
	case <-time.After(12 * time.Second):
		t.Fatal("live discovery stalled before the agent")
	}
	if w.Code == http.StatusMisdirectedRequest {
		t.Fatal("shared-host discovery rejected at the authority gate (421)")
	}
	if w.Code/100 != 5 {
		t.Fatalf("aborted discovery: status=%d, want 5xx", w.Code)
	}
	// Unknown route IDs fail closed with path-route semantics, not 421.
	if w := serveRoute(s, http.MethodGet, "public.example.org", "/.well-known/oauth-protected-resource/r/no-such-route/mcp", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown metadata route: got %d, want 404", w.Code)
	}
	// Revoked leases deny discovery exactly like tool traffic.
	insertMCPLeaseRow(t, db, "lse-mdhr", "mdhr.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateRevoked, 1, nil)
	if err := createMCPRoute(db, "public.example.org", "route-mdhr", "lse-mdhr", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	if w := serveRoute(s, http.MethodGet, "public.example.org", "/.well-known/oauth-protected-resource/r/route-mdhr/mcp", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("revoked metadata route: got %d, want 503", w.Code)
	}
	// Unrelated .well-known paths keep the 421: the fix must not loosen
	// the shared authority into a generic well-known router.
	if w := serveRoute(s, http.MethodGet, "public.example.org", "/.well-known/oauth-protected-resource/other", nil); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unrelated well-known: got %d, want 421", w.Code)
	}
	if w := serveRoute(s, http.MethodGet, "public.example.org", "/.well-known/nodeinfo", nil); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign well-known: got %d, want 421", w.Code)
	}
}

func TestMintRouteIDCharset(t *testing.T) {
	for i := 0; i < 25; i++ {
		id, err := MintRouteID()
		if err != nil {
			t.Fatal(err)
		}
		if !validRouteID(id) {
			t.Fatalf("minted route id %q fails its own validation", id)
		}
	}
	for _, bad := range []string{"", "a", "has space", "has/slash", "has.dot", "UPPER-ok-actually", "ಠ_ಠ"} {
		if bad == "UPPER-ok-actually" {
			continue // charset allows uppercase; listed for review only
		}
		if validRouteID(bad) {
			t.Errorf("validRouteID(%q) = true, want false", bad)
		}
	}
	if !validRouteID("UPPER-ok-actually") {
		t.Error("uppercase route IDs must be accepted (opaque identifiers)")
	}
}

func TestMCPRouteUnknownIDFailsClosed(t *testing.T) {
	s, _ := newMCPServer(t)
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/does-not-exist/mcp", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown route: got %d, want 404 (no hint, no fallthrough)", w.Code)
	}
}

func TestMCPRouteRequiresExactHost(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-a", "app.t.example.test", "protected", lease.StateActive, 1, nil)
	if err := createMCPRoute(db, "public.example.org", "route-a", "lse-a", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	// Same path on any other host must not resolve the route: an unknown
	// tunnel label fails closed without reaching the bound lease.
	for _, host := range []string{"evil.example.org", "app.t.example.test", "relay.example.test"} {
		w := serveRoute(s, http.MethodPost, host, "/r/route-a/mcp", nil)
		if w.Code == http.StatusOK {
			t.Fatalf("host %q resolved a foreign route", host)
		}
	}
}

func TestMCPRouteIgnoresForwardedHost(t *testing.T) {
	s, _ := newMCPServer(t)
	// A spoofed X-Forwarded-Host changes nothing: routing reads r.Host.
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/nope/mcp",
		map[string]string{"X-Forwarded-Host": "public.example.org"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("forwarded-host request: got %d, want 404", w.Code)
	}
}

func TestMCPRouteNoControlAPIViaRouteHost(t *testing.T) {
	s, _ := newMCPServer(t)
	// Agent control on the route host is misdirected, exactly as on any
	// non-relay host: route paths can never reach the control plane.
	for _, p := range []string{"/v1/agent/enroll", "/v1/agent/challenge", "/v1/agent/connect"} {
		w := serveRoute(s, http.MethodPost, "public.example.org", p, nil)
		if w.Code != http.StatusMisdirectedRequest {
			t.Fatalf("agent %s on route host: got %d, want 421", p, w.Code)
		}
	}
}

func TestMCPRouteExpiredLeaseDenied(t *testing.T) {
	s, db := newMCPServer(t)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	insertMCPLeaseRow(t, db, "lse-old", "old.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, &past)
	if err := createMCPRoute(db, "public.example.org", "route-old", "lse-old", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/route-old/mcp", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expired lease route: got %d, want 404", w.Code)
	}
	// The TTL side effect (evict + mark expired) is preserved on the path
	// ingress, matching wildcard behavior.
	var state string
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, "lse-old").Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != lease.StateExpired {
		t.Fatalf("expired lease not marked: status=%q", state)
	}
}

func TestMCPRouteRevokedLeaseDenied(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-rev", "rev.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateRevoked, 1, nil)
	if err := createMCPRoute(db, "public.example.org", "route-rev", "lse-rev", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/route-rev/mcp", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("revoked lease route: got %d, want 503", w.Code)
	}
}

func TestMCPRouteGenerationMismatchDenied(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-gen", "gen.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 2, nil)
	if err := createMCPRoute(db, "public.example.org", "route-gen", "lse-gen", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, "lse-gen", 1) // stale generation live
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/route-gen/mcp", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stale-generation route: got %d, want 503", w.Code)
	}
}

func TestMCPRouteFeatureOff(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	insertMCPLeaseRow(t, db, "lse-off", "off.t.example.test", "protected", lease.StateActive, 1, nil)
	if err := createMCPRoute(db, "public.example.org", "route-off", "lse-off", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	// Without MCPExternalHost the rows are inert: no path resolution.
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/route-off/mcp", nil)
	if w.Code == http.StatusOK || w.Code == http.StatusUnauthorized || w.Code == http.StatusServiceUnavailable {
		t.Fatalf("disabled feature routed: got %d", w.Code)
	}
}

func TestWantModeStrictEquality(t *testing.T) {
	cases := []struct {
		name   string
		intent LeaseIntent
		want   string
		fail   bool
	}{
		{"empty defaults protected", LeaseIntent{}, "protected", false},
		{"public flag", LeaseIntent{Public: true}, "public", false},
		{"explicit protected", LeaseIntent{AccessMode: "protected"}, "protected", false},
		{"explicit public", LeaseIntent{AccessMode: "public"}, "public", false},
		{"explicit oauth", LeaseIntent{AccessMode: AccessModeMCPUpstreamOAuth}, AccessModeMCPUpstreamOAuth, false},
		{"explicit fixture", LeaseIntent{AccessMode: AccessModeMCPAnonymousFixture}, AccessModeMCPAnonymousFixture, false},
		{"public flag plus explicit public", LeaseIntent{Public: true, AccessMode: "public"}, "public", false},
		{"public flag contradicts explicit oauth", LeaseIntent{Public: true, AccessMode: AccessModeMCPUpstreamOAuth}, "", true},
		{"unknown mode", LeaseIntent{AccessMode: "superuser"}, "", true},
	}
	for _, c := range cases {
		got, err := wantMode(c.intent)
		if c.fail {
			if err == nil {
				t.Errorf("%s: accepted invalid intent", c.name)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got (%q, %v), want (%q, nil)", c.name, got, err, c.want)
		}
	}
}

func TestCreateMCPRouteValidation(t *testing.T) {
	_, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-v", "v.t.example.test", "protected", lease.StateActive, 1, nil)
	for _, tc := range []struct {
		name, host, id, profile string
	}{
		{"empty id", "public.example.org", "", "upstream-oauth"},
		{"bad charset", "public.example.org", "a/b", "upstream-oauth"},
		{"bad profile", "public.example.org", "route-x", "superuser"},
		{"empty host", "", "route-x", "upstream-oauth"},
		{"missing lease", "public.example.org", "route-x", "upstream-oauth"},
	} {
		leaseID := "lse-v"
		if tc.name == "missing lease" {
			leaseID = "lse-missing"
		}
		if err := createMCPRoute(db, tc.host, tc.id, leaseID, tc.profile); err == nil {
			t.Errorf("createMCPRoute(%s) accepted invalid input", tc.name)
		}
	}
}

func TestMCPRouteOAuthPathParsing(t *testing.T) {
	cases := []struct {
		path string
		id   string
		fwd  string
		ok   bool
	}{
		{"/r/abc123/oauth/authorize", "abc123", "/oauth/authorize", true},
		{"/r/abc123/oauth/token", "abc123", "/oauth/token", true},
		{"/r/abc123/oauth/register", "abc123", "/oauth/register", true},
		{"/r/abc123/oauth/revoke", "abc123", "/oauth/revoke", true},
		{"/r/ABC-9_x/oauth/token", "ABC-9_x", "/oauth/token", true},
		{"/r/abc123/oauth/admin", "", "", false},    // not allowlisted
		{"/r/abc123/oauth/", "", "", false},         // empty endpoint
		{"/r/abc123/oauth", "", "", false},          // missing endpoint
		{"/r/abc123/oauth/token/", "", "", false},   // trailing slash
		{"/r/abc123/mcp", "", "", false},            // tool shape is not OAuth
		{"/r//oauth/token", "", "", false},          // empty route ID
		{"/r/abc%2fdef/oauth/token", "", "", false}, // encoded separator stays literal
		{"/r/abc123/OAuth/token", "", "", false},    // case-sensitive
	}
	for _, c := range cases {
		id, fwd, ok := parseMCPRouteOAuthPath(c.path)
		if ok != c.ok || id != c.id || fwd != c.fwd {
			t.Errorf("parseMCPRouteOAuthPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.path, id, fwd, ok, c.id, c.fwd, c.ok)
		}
	}
}

func TestMCPRouteASMetadataPathParsing(t *testing.T) {
	cases := []struct {
		path string
		id   string
		fwd  string
		ok   bool
	}{
		{"/.well-known/oauth-authorization-server/r/abc123/oauth", "abc123", "/.well-known/oauth-authorization-server", true},
		{"/.well-known/oauth-authorization-server/r/ABC-9_x/oauth", "ABC-9_x", "/.well-known/oauth-authorization-server", true},
		{"/.well-known/oauth-authorization-server/r/abc123/oauth/", "", "", false},
		{"/.well-known/oauth-authorization-server/r/abc123/mcp", "", "", false},
		{"/.well-known/oauth-authorization-server/r/abc123", "", "", false},
		{"/.well-known/oauth-authorization-server/r//oauth", "", "", false},
		{"/.well-known/oauth-authorization-server/r/abc%2fdef/oauth", "", "", false},
		{"/.well-known/oauth-authorization-server", "", "", false}, // server-root form is not route-scoped
		{"/.well-known/openid-configuration/r/abc123/oauth", "", "", false},
	}
	for _, c := range cases {
		id, fwd, ok := parseMCPRouteASMetadataPath(c.path)
		if ok != c.ok || id != c.id || fwd != c.fwd {
			t.Errorf("parseMCPRouteASMetadataPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.path, id, fwd, ok, c.id, c.fwd, c.ok)
		}
	}
}

func TestMCPRouteOAuthAdmitted(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-oa", "oa.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	liveFabricatedSession(t, s, "lse-oa", 1)
	if err := createMCPRoute(db, "public.example.org", "route-oa", "lse-oa", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	shapes := map[string]string{
		"/r/route-oa/oauth/authorize":                              "/oauth/authorize",
		"/r/route-oa/oauth/token":                                  "/oauth/token",
		"/r/route-oa/oauth/register":                               "/oauth/register",
		"/.well-known/oauth-authorization-server/r/route-oa/oauth": "/.well-known/oauth-authorization-server",
	}
	for public, wantFwd := range shapes {
		r := httptest.NewRequest(http.MethodGet, public, nil)
		r.Host = "public.example.org"
		tgt, sess, out, code := s.admitPathRoute(r)
		if code != 0 {
			t.Fatalf("%s denied: code=%d", public, code)
		}
		if tgt.LeaseID != "lse-oa" || sess == nil || !tgt.ViaPathRoute {
			t.Fatalf("%s admitted wrong target: %+v", public, tgt)
		}
		if out.URL.EscapedPath() != wantFwd {
			t.Fatalf("%s forwarded to %q, want %q", public, out.URL.EscapedPath(), wantFwd)
		}
	}
	// Unknown route IDs fail closed without reaching the lease.
	r := httptest.NewRequest(http.MethodGet, "/r/no-such-route/oauth/token", nil)
	r.Host = "public.example.org"
	if _, _, _, code := s.admitPathRoute(r); code != http.StatusNotFound {
		t.Fatalf("unknown OAuth route: got %d, want 404", code)
	}
	// A revoked lease denies OAuth endpoints exactly like tool traffic.
	insertMCPLeaseRow(t, db, "lse-oar", "oar.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateRevoked, 1, nil)
	if err := createMCPRoute(db, "public.example.org", "route-oar", "lse-oar", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/r/route-oar/oauth/token", nil)
	r2.Host = "public.example.org"
	if _, _, _, code := s.admitPathRoute(r2); code != http.StatusServiceUnavailable {
		t.Fatalf("revoked OAuth route: got %d, want 503", code)
	}
}

// TestSharedHostOAuthFullHandler proves the complete authority →
// admission → forwarding sequence for the route-scoped OAuth endpoints
// on a shared relay/MCP hostname. A live route must forward (the fake
// agent aborts, surfacing 5xx — never 421); a fixture-anonymous lease
// must deny the OAuth shapes with 404 while its tool path still works;
// unrelated paths keep the 421.
func TestSharedHostOAuthFullHandler(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{
		DB: db, Namespace: "t.example.test",
		RelayHost: "public.example.org", MCPExternalHost: "public.example.org",
	})
	if err != nil {
		t.Fatal(err)
	}
	insertMCPLeaseRow(t, db, "lse-oh", "oh.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	if err := createMCPRoute(db, "public.example.org", "route-oh", "lse-oh", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/r/route-oh/oauth/authorize", "/r/route-oh/oauth/token", "/r/route-oh/oauth/register", "/r/route-oh/oauth/revoke", "/.well-known/oauth-authorization-server/r/route-oh/oauth"} {
		// The dispatch harness serves exactly one stream: fresh
		// harness and session per shape.
		h := newDispatchHarness(t)
		insertRegistrySession(s, &Session{LeaseID: "lse-oh", Generation: 1, Yamux: h.relayYS,
			Budget: s.budgets.For("lse-oh"), closed: make(chan struct{})})
		w := serveRoute(s, http.MethodGet, "public.example.org", p, nil)
		select {
		case head := <-h.gotHead:
			if head.Generation != 1 || head.LeaseID != "lse-oh" {
				t.Fatalf("%s forwarded wrong head: %+v", p, head)
			}
		case <-h.noHead:
			t.Fatalf("live OAuth endpoint %s never reached the agent", p)
		case <-time.After(12 * time.Second):
			t.Fatalf("live OAuth endpoint %s stalled before the agent", p)
		}
		if w.Code == http.StatusMisdirectedRequest {
			t.Fatalf("shared-host OAuth endpoint %s rejected at the authority gate (421)", p)
		}
		if w.Code/100 != 5 {
			t.Fatalf("aborted OAuth endpoint %s: status=%d, want 5xx", p, w.Code)
		}
	}
	// Fixture-anonymous leases deny OAuth shapes with 404 (serveRouted
	// allowlist) while the tool path still admits.
	insertMCPLeaseRow(t, db, "lse-of", "of.t.example.test", AccessModeMCPAnonymousFixture, lease.StateActive, 1, nil)
	h2 := newDispatchHarness(t)
	insertRegistrySession(s, &Session{LeaseID: "lse-of", Generation: 1, Yamux: h2.relayYS,
		Budget: s.budgets.For("lse-of"), closed: make(chan struct{})})
	if err := createMCPRoute(db, "public.example.org", "route-of", "lse-of", "fixture-anonymous"); err != nil {
		t.Fatal(err)
	}
	if w := serveRoute(s, http.MethodPost, "public.example.org", "/r/route-of/oauth/token", nil); w.Code != http.StatusNotFound {
		t.Fatalf("fixture OAuth endpoint: got %d, want 404", w.Code)
	}
	// Denial happens before any stream opens, so the fake agent sees
	// nothing: assert no head arrived (gotHead would only fire if the
	// relay forwarded). noHead fires at harness teardown; a head would
	// be a failure.
	select {
	case head := <-h2.gotHead:
		t.Fatalf("fixture OAuth endpoint reached the agent: %+v", head)
	default:
	}
	// Unrelated OAuth-looking paths keep the 421.
	if w := serveRoute(s, http.MethodGet, "public.example.org", "/r/route-oh/oauth/admin", nil); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("non-allowlisted OAuth path: got %d, want 421", w.Code)
	}
	if w := serveRoute(s, http.MethodGet, "public.example.org", "/.well-known/oauth-authorization-server", nil); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("server-root AS metadata on shared host: got %d, want 421", w.Code)
	}
}
