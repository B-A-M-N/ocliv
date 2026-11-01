package relay

// MCP access-profile policy tests (P0-B). The route profile and the lease
// access mode must match exactly; every other combination — including an
// OAuth route to a protected or public lease — admits nothing. Ocliv
// visitor credentials are inapplicable inside MCP profiles: they are
// neither demanded, validated, nor fallen back to.

import (
	"net/http"
	"testing"

	"ocliv/internal/lease"
)

func TestMCPModeBindingMatrix(t *testing.T) {
	cases := []struct {
		profile IngressProfile
		mode    string
		want    bool
	}{
		{IngressMCPUpstreamOAuth, AccessModeMCPUpstreamOAuth, true},
		{IngressMCPAnonymousFixture, AccessModeMCPAnonymousFixture, true},
		{IngressMCPUpstreamOAuth, "protected", false},
		{IngressMCPUpstreamOAuth, "public", false},
		{IngressMCPAnonymousFixture, AccessModeMCPUpstreamOAuth, false},
		{IngressMCPAnonymousFixture, "protected", false},
		{IngressInvalid, AccessModeMCPUpstreamOAuth, false},
		{IngressMCPUpstreamOAuth, "", false},
	}
	for _, c := range cases {
		if got := mcpModeBinding(c.profile, c.mode); got != c.want {
			t.Errorf("mcpModeBinding(%v, %q) = %v, want %v", c.profile, c.mode, got, c.want)
		}
	}
	if !IsMCPMode(AccessModeMCPUpstreamOAuth) || !IsMCPMode(AccessModeMCPAnonymousFixture) {
		t.Error("MCP modes not recognized")
	}
	if IsMCPMode("protected") || IsMCPMode("public") || IsMCPMode("") {
		t.Error("generic modes misclassified as MCP modes")
	}
}

// TestMCPRouteModeMismatchDenied: an OAuth route bound to a protected
// lease — even one with a live generation-matched session — is an
// unsupported deployment combination. Binding precedes admission, so the
// denial is 404 (no hint) rather than the admission 503.
func TestMCPRouteModeMismatchDenied(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-mm", "mm.t.example.test", "protected", lease.StateActive, 1, nil)
	liveFabricatedSession(t, s, "lse-mm", 1)
	if err := createMCPRoute(db, "public.example.org", "route-mm", "lse-mm", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/route-mm/mcp", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("mismatched route: got %d, want 404", w.Code)
	}
}

// TestMCPRoutePublicLeaseDenied: routes add nothing to public leases and
// must not be bindable to them.
func TestMCPRoutePublicLeaseDenied(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-pub", "pub.t.example.test", "public", lease.StateActive, 1, nil)
	liveFabricatedSession(t, s, "lse-pub", 1)
	if err := createMCPRoute(db, "public.example.org", "route-pub", "lse-pub", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/route-pub/mcp", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("public-lease route: got %d, want 404", w.Code)
	}
}

// TestMCPRouteFixtureBinding: the anonymous-fixture profile binds only
// to fixture-mode leases.
func TestMCPRouteFixtureBinding(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-fx", "fx.t.example.test", AccessModeMCPAnonymousFixture, lease.StateActive, 1, nil)
	liveFabricatedSession(t, s, "lse-fx", 1)
	if err := createMCPRoute(db, "public.example.org", "route-fx", "lse-fx", "fixture-anonymous"); err != nil {
		t.Fatal(err)
	}
	tgt, sess, profile, code := s.resolveMCPRouteID("route-fx")
	if code != 0 {
		t.Fatalf("bound fixture route denied: code=%d", code)
	}
	if tgt.LeaseID != "lse-fx" || sess == nil || profile != IngressMCPAnonymousFixture || !tgt.ViaPathRoute {
		t.Fatalf("fixture route admitted wrong target: %+v", tgt)
	}
	// Same route shape against an OAuth-mode lease is a mismatch.
	insertMCPLeaseRow(t, db, "lse-fx2", "fx2.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	if err := createMCPRoute(db, "public.example.org", "route-fx2", "lse-fx2", "fixture-anonymous"); err != nil {
		t.Fatal(err)
	}
	w := serveRoute(s, http.MethodPost, "public.example.org", "/r/route-fx2/mcp", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-profile route: got %d, want 404", w.Code)
	}
}

// TestMCPRouteCrossTenantIsolation: with two live leases, a route admits
// exactly its bound lease — never the neighbor.
func TestMCPRouteCrossTenantIsolation(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-ta", "ta.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	insertMCPLeaseRow(t, db, "lse-tb", "tb.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	liveFabricatedSession(t, s, "lse-ta", 1)
	liveFabricatedSession(t, s, "lse-tb", 1)
	if err := createMCPRoute(db, "public.example.org", "route-tb", "lse-tb", "upstream-oauth"); err != nil {
		t.Fatal(err)
	}
	tgt, _, _, code := s.resolveMCPRouteID("route-tb")
	if code != 0 {
		t.Fatalf("bound route denied: code=%d", code)
	}
	if tgt.LeaseID != "lse-tb" || tgt.Hostname != "tb.t.example.test" {
		t.Fatalf("route admitted wrong tenant: %+v", tgt)
	}
}
