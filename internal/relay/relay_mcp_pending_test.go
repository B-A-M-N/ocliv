// Pending-verification publication lifecycle tests (P0-A). A newly
// registered publication must deny ordinary public tool execution
// until the publisher proves (via OAuth discovery) and activates the
// binding. Only the discovery metadata path stays reachable while
// pending — it carries public metadata, never tool execution. Crash
// or kill between registration and activation fails closed: the row
// stays pending and denies after reconnects and restarts.
package relay

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ocliv/internal/lease"
)

// postMCPActivate POSTs a signed route activation through the full
// handler stack, returning status and body.
func postMCPActivate(t *testing.T, s *Server, priv ed25519.PrivateKey, keyID, leaseID, routeID string) (int, string) {
	t.Helper()
	path := "/v1/agent/lease/" + leaseID + "/mcp-route/" + routeID + "/activate"
	r := signedMgmtRequest(t, priv, keyID, http.MethodPost, path)
	r.Host = "relay.example.test"
	r.RequestURI = path
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// A freshly registered publication denies the tool path: registration
// is not readiness. Pre-fix this admits (code 0); post-fix it is 404.
func TestPendingPublicationDeniesToolPath(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-pend", "pend.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	liveFabricatedSession(t, s, "lse-pend", 1)
	r1 := publishRoute(t, s, priv, "key-test", "lse-pend", "upstream-oauth")
	r := httptest.NewRequest(http.MethodPost, "/r/"+r1+"/mcp", nil)
	r.Host = "public.example.org"
	if _, _, _, code := s.admitPathRoute(r); code != http.StatusNotFound {
		t.Fatalf("pending publication tool path: code=%d, want 404", code)
	}
}

// The discovery metadata path stays reachable while pending: the
// publisher's own verification probe must pass through the live
// binding. Tool execution is what is denied, not discovery.
func TestPendingPublicationAllowsDiscovery(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-pendmd", "pendmd.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	liveFabricatedSession(t, s, "lse-pendmd", 1)
	r1 := publishRoute(t, s, priv, "key-test", "lse-pendmd", "upstream-oauth")
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/r/"+r1+"/mcp", nil)
	r.Host = "public.example.org"
	tgt, _, out, code := s.admitPathRoute(r)
	if code != 0 || tgt == nil {
		t.Fatalf("pending publication discovery denied: code=%d", code)
	}
	if out.URL.EscapedPath() != "/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("discovery forward path = %q", out.URL.EscapedPath())
	}
}

// Activation is an explicit, ownership-bound CAS: after a signed
// activate on the bound lease, the tool path admits. Pre-fix there is
// no activate endpoint (404); post-fix it is 200 then admission.
func TestActivationOpensToolPath(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-act", "act.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	liveFabricatedSession(t, s, "lse-act", 1)
	r1 := publishRoute(t, s, priv, "key-test", "lse-act", "upstream-oauth")
	if code, body := postMCPActivate(t, s, priv, "key-test", "lse-act", r1); code != http.StatusOK {
		t.Fatalf("activate: status=%d body=%s, want 200", code, body)
	}
	r := httptest.NewRequest(http.MethodPost, "/r/"+r1+"/mcp", nil)
	r.Host = "public.example.org"
	if _, _, _, code := s.admitPathRoute(r); code != 0 {
		t.Fatalf("activated publication tool path denied: code=%d", code)
	}
	// Replay is idempotent: a second activate still reports 200.
	if code, _ := postMCPActivate(t, s, priv, "key-test", "lse-act", r1); code != http.StatusOK {
		t.Fatalf("replay activate: status=%d, want 200", code)
	}
}

// Activation binds the exact lease: another lease owned by the same
// key cannot activate the row, and activation after revoke fails.
func TestActivationBindsLease(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-own", "own.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	insertMCPLeaseRow(t, db, "lse-other", "other.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	r1 := publishRoute(t, s, priv, "key-test", "lse-own", "upstream-oauth")
	if code, _ := postMCPActivate(t, s, priv, "key-test", "lse-other", r1); code != http.StatusConflict {
		t.Fatalf("cross-lease activate: status=%d, want 409", code)
	}
	if err := s.revokeLease("lse-own"); err != nil {
		t.Fatal(err)
	}
	if code, _ := postMCPActivate(t, s, priv, "key-test", "lse-own", r1); code != http.StatusConflict {
		t.Fatalf("post-revoke activate: status=%d, want 409", code)
	}
}

// A killed publisher (register without activate) stays denied across
// a replacement generation: pending is a durable property of the
// publication, not of the session that registered it.
func TestPendingSurvivesReplacementGeneration(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-crash", "crash.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	liveFabricatedSession(t, s, "lse-crash", 1)
	r1 := publishRoute(t, s, priv, "key-test", "lse-crash", "upstream-oauth")
	// Simulate publisher death + replacement lease rebind (same name).
	if err := s.closeLeaseDurable("lse-crash"); err != nil {
		t.Fatal(err)
	}
	insertMCPLeaseRow(t, db, "lse-crash2", "crash2.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	relabel(t, db, "lse-crash2", "crash")
	liveFabricatedSession(t, s, "lse-crash2", 1)
	r2 := publishRoute(t, s, priv, "key-test", "lse-crash2", "upstream-oauth")
	if r2 != r1 {
		t.Fatalf("rebind minted %q, want stable %q", r2, r1)
	}
	r := httptest.NewRequest(http.MethodPost, "/r/"+r1+"/mcp", nil)
	r.Host = "public.example.org"
	if _, _, _, code := s.admitPathRoute(r); code != http.StatusNotFound {
		t.Fatalf("unactivated rebound publication tool path: code=%d, want 404", code)
	}
}

// A verified publication rebound to a replacement lease must not
// inherit verification: the new upstream binding is unproven until it
// passes discovery verification and activation itself. Same-lease
// re-publish stays idempotent and keeps its verified state.
func TestRebindResetsVerification(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-v1", "vlab.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-v1", "upstream-oauth")
	if code, _ := postMCPActivate(t, s, priv, "key-test", "lse-v1", r1); code != http.StatusOK {
		t.Fatalf("initial activate: status=%d, want 200", code)
	}
	// Same-lease re-publish is idempotent: verified state preserved.
	if r := publishRoute(t, s, priv, "key-test", "lse-v1", "upstream-oauth"); r != r1 {
		t.Fatalf("same-lease republish minted %q, want stable %q", r, r1)
	}
	// Replacement lease under the same name rebinds the stable route.
	if err := s.closeLeaseDurable("lse-v1"); err != nil {
		t.Fatal(err)
	}
	insertMCPLeaseRow(t, db, "lse-v2", "other.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	relabel(t, db, "lse-v2", "vlab")
	liveFabricatedSession(t, s, "lse-v2", 1)
	if r2 := publishRoute(t, s, priv, "key-test", "lse-v2", "upstream-oauth"); r2 != r1 {
		t.Fatalf("rebind minted %q, want stable %q", r2, r1)
	}
	var verified *string
	if err := db.SQL().QueryRow(`SELECT verified_at FROM mcp_publications WHERE route_id=?`, r1).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if verified != nil {
		t.Fatalf("rebound publication kept verified_at=%q without fresh qualification", *verified)
	}
	toolReq := func() int {
		r := httptest.NewRequest(http.MethodPost, "/r/"+r1+"/mcp", nil)
		r.Host = "public.example.org"
		_, _, _, code := s.admitPathRoute(r)
		return code
	}
	if code := toolReq(); code != http.StatusNotFound {
		t.Fatalf("rebound unverified tool path: code=%d, want 404 (no upstream execution)", code)
	}
	// Stale activation from the superseded lease must fail.
	if code, _ := postMCPActivate(t, s, priv, "key-test", "lse-v1", r1); code != http.StatusConflict {
		t.Fatalf("stale-lease activate: status=%d, want 409", code)
	}
	// Fresh qualification on the replacement binding re-opens the path.
	if code, _ := postMCPActivate(t, s, priv, "key-test", "lse-v2", r1); code != http.StatusOK {
		t.Fatalf("re-activate: status=%d, want 200", code)
	}
	if code := toolReq(); code != 0 {
		t.Fatalf("re-verified tool path denied: code=%d", code)
	}
}

// Automatic named-lease reclaim carries the publication to the
// replacement lease, but must not carry its verification: the new
// upstream binding admits no tool traffic until re-verified.
func TestReclaimResetsVerification(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	label := "reclaim-verify"
	ls, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPUpstreamOAuth}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	r1 := publishRoute(t, s, priv, "key-test", ls.ID, "upstream-oauth")
	if code, _ := postMCPActivate(t, s, priv, "key-test", ls.ID, r1); code != http.StatusOK {
		t.Fatalf("initial activate: status=%d, want 200", code)
	}
	ls2, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPUpstreamOAuth}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	var bound string
	var verified *string
	if err := db.SQL().QueryRow(`SELECT lease_id, verified_at FROM mcp_publications WHERE route_id=?`, r1).Scan(&bound, &verified); err != nil {
		t.Fatal(err)
	}
	if bound != ls2.ID {
		t.Fatalf("reclaim bound publication to %q, want %s", bound, ls2.ID)
	}
	if verified != nil {
		t.Fatalf("reclaimed publication kept verified_at=%q without fresh qualification", *verified)
	}
	liveFabricatedSession(t, s, ls2.ID, 1)
	r := httptest.NewRequest(http.MethodPost, "/r/"+r1+"/mcp", nil)
	r.Host = "public.example.org"
	if _, _, _, code := s.admitPathRoute(r); code != http.StatusNotFound {
		t.Fatalf("reclaimed unverified tool path: code=%d, want 404 (no upstream execution)", code)
	}
	if code, _ := postMCPActivate(t, s, priv, "key-test", ls2.ID, r1); code != http.StatusOK {
		t.Fatalf("re-activate after reclaim: status=%d, want 200", code)
	}
}

// Activation requires an ACTIVE, unexpired, correctly owned lease at
// activation time: a lease that died after registration cannot be
// used to verify the binding.
func TestActivateRequiresActiveLease(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-doomed", "doomed.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-doomed", "upstream-oauth")
	if err := s.closeLeaseDurable("lse-doomed"); err != nil {
		t.Fatal(err)
	}
	if code, _ := postMCPActivate(t, s, priv, "key-test", "lse-doomed", r1); code != http.StatusConflict {
		t.Fatalf("activate on closed lease: status=%d, want 409", code)
	}
}

// A lease with a pending publication does not serve tool traffic on
// its wildcard hostname either; a lease with no publications at all
// (mcp serve, no publish) is unaffected.
func TestWildcardPendingDeniesToolPath(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-wild", "wild.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	liveFabricatedSession(t, s, "lse-wild", 1)
	r1 := publishRoute(t, s, priv, "key-test", "lse-wild", "upstream-oauth")
	tgt, sess, code := s.route("wild.t.example.test")
	if code != 0 {
		t.Fatalf("wildcard route admission: code=%d", code)
	}
	req := httptest.NewRequest(http.MethodPost, "http://wild.t.example.test/mcp", nil)
	req.RequestURI = "/mcp"
	rec := httptest.NewRecorder()
	s.serveRouted(rec, req, tgt, sess)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("wildcard pending tool path: code=%d, want 404", rec.Code)
	}
	_ = r1
}
