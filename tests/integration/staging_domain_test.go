package integration

import (
	"net/http"
	"testing"

	"ocliv/internal/config"
)

// The staging deployment is a normal relay under a staging namespace, not
// a bypassed implementation: a named lease on the ocliv.test registry must
// receive its authority under t.ocliv.test, stay protected by default, and
// a same-label name from any other domain must not resolve through this
// registry (P0-03).
func TestStagingDomainAuthority(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.ocliv.test", "relay.ocliv.test")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{Name: "demo"})
	if got := h.host(); got != "demo.t.ocliv.test" {
		t.Fatalf("lease authority = %q, want demo.t.ocliv.test", got)
	}
	// Baseline after attach: the agent's own readiness probe already hit
	// the app; only visitor-caused hits after this point count as leaks.
	before := app.Hits()
	resp := h.visitorReq(t, "GET", "/", nil, nil)
	resp.Body.Close()
	// Protected leases deny unauthenticated visitors (401) or redirect
	// them to the unlock flow (302); either way nothing is forwarded.
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusFound {
		t.Fatalf("unauthorized staging visitor: got %d want 401/302", resp.StatusCode)
	}
	// Same label, foreign domain: not resolved by this registry.
	probe := probeRoute(t, h.relay, "demo.t.example.test")
	if probe != http.StatusNotFound && probe != http.StatusBadRequest && probe != http.StatusMisdirectedRequest {
		t.Fatalf("foreign-domain host routed: got %d", probe)
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("foreign/unauthorized probes reached local app %d times", got)
	}
}
