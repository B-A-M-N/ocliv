package integration

// MCP hosting boundary (Phase 6): an MCP-style HTTP API (JSON-RPC over
// POST) uses the ordinary secure forwarding path with no relay changes.
// The V1.1 stdio adapter (internal/mcp, ocliv mcp expose) meets the same
// bar — authenticated visitor, no direct relay internals — and its
// through-tunnel behavior is pinned in mcp_stdio_test.go; the boundary
// below pins the transport that needs no adapter: HTTP.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestMCPHeaderPreservation pins the thin-extension contract (MCP
// amendment P0-4, M03/M05): the tunnel forwards application
// authorization and MCP protocol headers byte-for-byte, strips Ocliv's
// own credential even when a visitor spoofs it, and imposes no
// same-origin policy of its own on non-browser clients — Origin is
// preserved so the hosted MCP server enforces its configured policy.
// The 2026-07-28 stateless transport needs no session id, but a legacy
// Mcp-Session-Id must still pass through untouched.
func TestMCPHeaderPreservation(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	// Header-token auth is the non-browser MCP path: cookie CSRF rules
	// don't apply, so a foreign Origin must pass through for the app's
	// own origin policy instead of being rejected (or stripped) by the
	// tunnel. Cookie+foreign-Origin stays 403 via CheckCSRF (see
	// TestCSRFEnforcement); spoofed relay credentials never reach the
	// app even when presented (see adversarial header-token test).
	raw := shareRaw(t, h)
	hdrs := map[string]string{
		"X-Ocliv-Authorization": "Bearer " + raw,
		"Authorization":         "Bearer [REDACTED]",
		"Content-Type":          "application/json",
		"Accept":                "application/json, text/event-stream",
		"MCP-Protocol-Version":  "2026-07-28",
		"Mcp-Session-Id":        "legacy-session-1",
		"Origin":                "https://mcp-client.example",
	}
	resp := h.visitorReq(t, http.MethodPost, "/headers", strings.NewReader(`{}`), hdrs)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized /headers status=%d, want 200", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["app_auth"] != "Bearer [REDACTED]" {
		t.Errorf("app Authorization not preserved: %q", got["app_auth"])
	}
	if got["relay_auth"] != "" {
		t.Errorf("spoofed relay credential reached app: %q", got["relay_auth"])
	}
	if got["mcp_protocol_version"] != "2026-07-28" {
		t.Errorf("MCP-Protocol-Version not preserved: %q", got["mcp_protocol_version"])
	}
	if got["mcp_session_id"] != "legacy-session-1" {
		t.Errorf("Mcp-Session-Id not preserved: %q", got["mcp_session_id"])
	}
	if got["origin"] != "https://mcp-client.example" {
		t.Errorf("Origin not preserved for app policy: %q", got["origin"])
	}
	if got := app.hits.Load(); got == 0 {
		t.Errorf("authorized header probe never reached the app")
	}
}

// TestExplicitInvalidCredentialNoCookieFallback (M14): an explicit
// invalid relay credential is a hard 401 even when the same request
// carries a valid session cookie. Authentication failure never
// downgrades to a weaker-but-valid credential, and the denied request
// never reaches the local app.
func TestExplicitInvalidCredentialNoCookieFallback(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	cookie := redeem(t, h)
	before := app.hits.Load()
	hdrs := map[string]string{
		"Cookie":                cookie,
		"X-Ocliv-Authorization": "Bearer garbage-spoofed-token",
	}
	resp := h.visitorReq(t, http.MethodGet, "/", strings.NewReader(""), hdrs)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("explicit-invalid + valid-cookie status=%d, want 401", resp.StatusCode)
	}
	if got := app.hits.Load(); got != before {
		t.Fatalf("denied request reached the app (%d hits)", got-before)
	}
}

func TestMCPOverOrdinaryForwardingPath(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	const rpcBody = `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}`
	jsonHeaders := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}
	before := app.hits.Load()

	// 1. Unauthorized JSON-RPC: denied before forwarding; the app that
	// would serve tools is never contacted.
	resp := h.visitorReq(t, http.MethodPost, "/mcp", strings.NewReader(rpcBody), jsonHeaders)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("unauthorized MCP request returned 200")
	}
	if got := app.hits.Load(); got != before {
		t.Fatalf("unauthorized MCP request reached the app (%d hits)", got-before)
	}

	// 2. Authorized JSON-RPC: full round trip through the ordinary
	// protected path, response body intact.
	cookie := redeem(t, h)
	hdrs := authedHeaders(cookie)
	hdrs["Content-Type"] = "application/json"
	hdrs["Accept"] = "application/json"
	hdrs["Origin"] = "http://" + h.host()
	resp2 := h.visitorReq(t, http.MethodPost, "/mcp", strings.NewReader(rpcBody), hdrs)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("authorized MCP status=%d, want 200", resp2.StatusCode)
	}
	got, err := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"tools":[]`) {
		t.Fatalf("MCP response corrupted: %q", got)
	}
	if got := app.hits.Load(); got == before {
		t.Fatalf("authorized MCP request never reached the app")
	}
}
