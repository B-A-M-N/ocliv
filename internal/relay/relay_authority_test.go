package relay

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ocliv/internal/store"
)

// Authority split: agent control serves only on the relay authority (or
// direct loopback); visitor traffic only on tunnel hosts (or direct
// loopback). Unknown authority must fail without reaching either handler
// class (P0 hostname-specific control-plane boundaries).
func newAuthorityServer(t *testing.T) *Server {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func serveHost(s *Server, method, path, host string) int {
	r := httptest.NewRequest(method, path, nil)
	r.Host = host
	// httptest defaults RemoteAddr to a documentation IP; tests that
	// expect same-machine dispatch must opt into a loopback peer.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}

func servePeer(s *Server, method, path, host, remote string) int {
	r := httptest.NewRequest(method, path, nil)
	r.Host = host
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}

func TestAgentPathsRequireRelayAuthority(t *testing.T) {
	s := newAuthorityServer(t)
	for _, p := range []string{"/v1/agent/enroll", "/v1/agent/challenge", "/v1/agent/connect"} {
		if code := serveHost(s, http.MethodPost, p, "x.t.example.test"); code != http.StatusMisdirectedRequest {
			t.Errorf("agent %s on tunnel host: got %d want 421", p, code)
		}
		if code := serveHost(s, http.MethodPost, p, "evil.test"); code != http.StatusMisdirectedRequest {
			t.Errorf("agent %s on unknown host: got %d want 421", p, code)
		}
		if code := serveHost(s, http.MethodPost, p, "relay.example.test"); code == http.StatusMisdirectedRequest {
			t.Errorf("agent %s on relay host: got 421, want handler dispatch", p)
		}
		if code := servePeer(s, http.MethodPost, p, "127.0.0.1", "127.0.0.1:9999"); code != http.StatusMisdirectedRequest {
			t.Errorf("agent %s with loopback Host from loopback peer: got %d want 421", p, code)
		}
	}
}

func TestPublicPathsRequireTunnelAuthority(t *testing.T) {
	s := newAuthorityServer(t)
	if code := serveHost(s, http.MethodGet, "/", "relay.example.test"); code != http.StatusMisdirectedRequest {
		t.Errorf("public / on relay host: got %d want 421", code)
	}
	// Foreign and in-namespace-unknown hosts fall through to the legacy
	// router, which fails closed without forwarding: 404, never 421 and
	// never a proxied response.
	for _, h := range []string{"evil.test", "nope.t.example.test", "a.b.t.example.test"} {
		if code := serveHost(s, http.MethodGet, "/", h); code != http.StatusNotFound && code != http.StatusBadRequest {
			t.Errorf("public / on %q: got %d want fail-closed 400/404", h, code)
		}
	}
	if code := servePeer(s, http.MethodGet, "/", "127.0.0.1:8080", "127.0.0.1:9999"); code == http.StatusMisdirectedRequest {
		t.Errorf("public / from loopback peer: got 421, want handler dispatch")
	}
}

// TestControlAuthorityCannotBeSpoofedThroughEdge: a client-supplied
// localhost/loopback Host VALUE grants no authority by itself. Only the
// configured relay hostname or a kernel-enforced loopback PEER dispatches
// to agent control. Requests that look "local" by header but arrive from a
// non-loopback peer are rejected (P0-04).
func TestControlAuthorityCannotBeSpoofedThroughEdge(t *testing.T) {
	s := newAuthorityServer(t)
	spoofed := []string{"localhost", "localhost:8080", "127.0.0.1", "127.0.0.1:8080", "[::1]", "LOCALHOST"}
	for _, h := range spoofed {
		for _, p := range []string{"/v1/agent/enroll", "/v1/agent/challenge", "/v1/agent/connect"} {
			if code := servePeer(s, http.MethodPost, p, h, "203.0.113.7:5000"); code != http.StatusMisdirectedRequest {
				t.Errorf("agent %s with spoofed Host %q from foreign peer: got %d want 421", p, h, code)
			}
		}
	}
	// Edge-forwarded shape: loopback peer (Caddy) but foreign authority.
	// The relay enforces control-plane authority itself (P0-04): agent
	// paths on anything but the relay hostname or a direct loopback name
	// fail with 421 before reaching any handler. Edge Caddy filtering
	// (no catch-all site; tests/staging/check-edge.sh) stays the outer
	// layer; this is defense in depth at the relay.
	for _, p := range []string{"/v1/agent/enroll", "/v1/agent/challenge", "/v1/agent/connect"} {
		if code := servePeer(s, http.MethodPost, p, "attacker.test", "127.0.0.1:5000"); code != http.StatusMisdirectedRequest {
			t.Errorf("agent %s for foreign authority via edge peer: got %d want 421", p, code)
		}
	}
	// Same spoofed values from a loopback peer must NOT dispatch: strict
	// relay authority (MCP amendment P0). Same-machine callers and tests
	// name the relay authority explicitly while dialing loopback.
	for _, h := range spoofed {
		if code := servePeer(s, http.MethodPost, "/v1/agent/challenge", h, "127.0.0.1:5000"); code != http.StatusMisdirectedRequest {
			t.Errorf("agent challenge with Host %q from loopback peer: got %d want 421", h, code)
		}
	}
}

// TestAgentPathsRequireRelayAuthorityEvenFromLoopback: strict boundary
// (MCP amendment P0): agent control requires the configured relay
// authority even when the peer is loopback. A loopback Host VALUE from a
// loopback peer must not dispatch — Caddy also forwards over loopback, so
// peer identity alone cannot authorize the control plane. Only the exact
// relay hostname (port-insensitive) dispatches to agent handlers.
// TestSameHostMCPPathReachesRouteResolution: a single-host edge serves
// agent control AND /r/<route-id>/mcp on one FQDN
// (packaging/caddy/Caddyfile.single-host, temporary *.ts.net ingress).
// authorizeHost must let route-shaped MCP paths through to handlePublic
// admission instead of 421ing them as visitor traffic on the control
// authority. Unknown routes then fail closed with 404 (never 421, never
// the control API); non-route paths on the shared host keep the 421, and
// agent control keeps strict dispatch.
func TestSameHostMCPPathReachesRouteResolution(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{DB: db, Namespace: "t.example.test",
		RelayHost: "relay.example.test", MCPExternalHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	// Route-shaped path on the shared host reaches path-route admission:
	// an unknown route fails closed with 404, not 421.
	if code := serveHost(s, http.MethodGet, "/r/abc123XYZ_-/mcp", "relay.example.test"); code != http.StatusNotFound {
		t.Errorf("route-shaped MCP path on shared host: got %d want 404 (route resolution, not 421)", code)
	}
	// Malformed route shape on the shared host keeps the 421.
	if code := serveHost(s, http.MethodGet, "/r/ab/mcp", "relay.example.test"); code != http.StatusMisdirectedRequest {
		t.Errorf("malformed route path on shared host: got %d want 421", code)
	}
	// Ordinary paths on the shared host keep the 421.
	if code := serveHost(s, http.MethodGet, "/", "relay.example.test"); code != http.StatusMisdirectedRequest {
		t.Errorf("public / on shared host: got %d want 421", code)
	}
	// Agent control on the shared host still dispatches (not 421).
	if code := serveHost(s, http.MethodPost, "/v1/agent/challenge", "relay.example.test"); code == http.StatusMisdirectedRequest {
		t.Errorf("agent challenge on shared host: got 421, want handler dispatch")
	}
	// Without single-host configured, the same path keeps the 421.
	plain := newAuthorityServer(t)
	if code := serveHost(plain, http.MethodGet, "/r/abc123XYZ_-/mcp", "relay.example.test"); code != http.StatusMisdirectedRequest {
		t.Errorf("route-shaped path without mcp-host: got %d want 421", code)
	}
}

func TestAgentPathsRequireRelayAuthorityEvenFromLoopback(t *testing.T) {
	s := newAuthorityServer(t)
	for _, h := range []string{"localhost", "localhost:8080", "127.0.0.1", "127.0.0.1:8080", "[::1]", "LOCALHOST"} {
		for _, p := range []string{"/v1/agent/enroll", "/v1/agent/challenge", "/v1/agent/connect"} {
			if code := servePeer(s, http.MethodPost, p, h, "127.0.0.1:5000"); code != http.StatusMisdirectedRequest {
				t.Errorf("agent %s with loopback Host %q from loopback peer: got %d want 421", p, h, code)
			}
		}
	}
}

// TestAgentPathsRejectTunnelAuthorityThroughEdge: an agent control path
// addressed to a TUNNEL hostname must never dispatch, even when forwarded
// over loopback by the edge. Otherwise visitor-authority requests reach
// the control plane (P0-04 residual boundary).
func TestAgentPathsRejectTunnelAuthorityThroughEdge(t *testing.T) {
	s := newAuthorityServer(t)
	for _, h := range []string{"demo.t.example.test", "demo.t.example.test:8444", "DEMO.T.EXAMPLE.TEST"} {
		for _, p := range []string{"/v1/agent/enroll", "/v1/agent/challenge", "/v1/agent/connect"} {
			if code := servePeer(s, http.MethodPost, p, h, "127.0.0.1:5000"); code != http.StatusMisdirectedRequest {
				t.Errorf("agent %s on tunnel Host %q via edge peer: got %d want 421", p, h, code)
			}
		}
	}
}
