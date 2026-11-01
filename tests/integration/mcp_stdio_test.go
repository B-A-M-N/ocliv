package integration

// V1.1 stdio-adapter integration (M07/M11/M12): the bundled adapter serves
// an operator-selected stdio child (here: cat, the deterministic echo
// stand-in) and the agent forwards tunnel traffic to its loopback port.
// The tunnel path performs no JSON-RPC parsing — bytes in, same bytes out
// — and authorization still gates every request before any stream opens.

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"ocliv/internal/mcp"
)

// adapterUpstream starts a cat-backed adapter and returns its loopback
// port for the harness agent to forward to.
func adapterUpstream(t *testing.T) int {
	t.Helper()
	a, err := mcp.New(mcp.Options{Command: "cat"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, portStr, err := net.SplitHostPort(a.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// TestStdioAdapterThroughTunnel: an authorized JSON-RPC call round-trips
// through relay → agent → stdio child byte-for-byte, while an
// unauthenticated call is denied.
func TestStdioAdapterThroughTunnel(t *testing.T) {
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, adapterUpstream(t))

	const rpcBody = `{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}`
	hdrs := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}

	// 1. Unauthorized: denied before any stream reaches the child.
	resp := h.visitorReq(t, http.MethodPost, "/", strings.NewReader(rpcBody), hdrs)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("unauthorized adapter call returned 200")
	}

	// 2. Authorized: the stdio child echoes the exact message.
	raw := shareRaw(t, h)
	authHdrs := map[string]string{
		"X-Ocliv-Authorization": "Bearer " + raw,
		"Content-Type":          "application/json",
		"Accept":                "application/json, text/event-stream",
	}
	resp2 := h.visitorReq(t, http.MethodPost, "/", strings.NewReader(rpcBody), authHdrs)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("authorized adapter call status=%d, want 200", resp2.StatusCode)
	}
	got, err := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != rpcBody+"\n" {
		t.Fatalf("adapter echo mismatch: got %q want %q", got, rpcBody+"\n")
	}
}

// TestRemoteManagementDeniedViaTunnel (M12): even a valid visitor
// credential cannot reach agent management through the tunnel. The
// authority boundary rejects it (421) before any lease lookup — the bogus
// lease ID proves denial precedes resolution — and no management listener
// exists on the visitor path.
func TestRemoteManagementDeniedViaTunnel(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	raw := shareRaw(t, h)
	hdrs := map[string]string{
		"X-Ocliv-Authorization": "Bearer " + raw,
		"Content-Type":          "application/json",
	}
	before := app.hits.Load()
	resp := h.visitorReq(t, http.MethodPost, "/v1/agent/lease/no-such-lease/revoke", strings.NewReader(`{}`), hdrs)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("visitor management attempt status=%d, want 421", resp.StatusCode)
	}
	if got := app.hits.Load(); got != before {
		t.Fatalf("management probe reached the app (%d hits)", got-before)
	}
}
