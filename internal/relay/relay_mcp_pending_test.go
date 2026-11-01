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
