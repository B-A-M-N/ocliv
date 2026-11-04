package integration

// Composed Ocliv x Metis vertical against a REAL Metis MCP server: Metis
// runs as a subprocess (skip-gated on OCLIV_METIS_BIN, mirroring Metis's
// own METIS_OCLIV_BIN gate), real RS256 bearer tokens are minted by the
// committed tests/staging/metis-idp scaffold, and the visitor's
// tools/list crosses the public path route relay -> agent -> Metis with
// Metis itself validating the bearer. Negative cases pin the 401
// authorization contract (wrong audience, missing bearer).
//
// Without OCLIV_METIS_BIN the test skips, so the default gate stays green.

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"ocliv/internal/config"
)

// metisExpectedToolCount is the tool list Metis serves with the
// admin,tasks,message remote-capability set (re-measured against a real
// Metis build; see the assertion below for the shape constraints).
const metisExpectedToolCount = 15

// TestMetisComposedPublicRouteRealBearerAuth drives the composed chain
// end to end through the PUBLIC route: real Metis upstream, real RS256
// bearer, real relay+agent forwarding. Nothing calls Metis directly —
// every request enters at /r/<route-id>/mcp on the external host.
func TestMetisComposedPublicRouteRealBearerAuth(t *testing.T) {
	bin := metisBinPath(t)
	work := t.TempDir()
	idpBin := metisBuildIDP(t, work)
	keyPEM, jwks := metisIDPGenKey(t, idpBin, filepath.Join(work, "idp"))
	m := metisStartServer(t, bin, jwks, filepath.Join(work, "state"), filepath.Join(work, "handoff"))
	m.waitReady(t)

	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	// The agent forwards to the REAL Metis instead of a fake local app.
	h.startAgentOpts(t, m.port, config.Agent{AccessMode: "mcp_upstream_oauth"})

	code, routeID, routeURL, auth := mgmtRouteCreate(t, h, "upstream-oauth")
	if code != http.StatusOK {
		t.Fatalf("route create status=%d", code)
	}
	if routeID == "" || auth != "upstream-oauth" {
		t.Fatalf("route create reply incomplete: id=%q auth=%q", routeID, auth)
	}
	if want := "https://public.example.org/r/" + routeID + "/mcp"; routeURL != want {
		t.Fatalf("route url=%q want %q", routeURL, want)
	}
	mgmtRouteActivate(t, h, routeID)

	// The Ocliv->Metis handoff: Metis re-reads the resource file per
	// request, so the route URL is written after the route exists.
	m.writeResource(t, routeURL)

	// --- Positive: valid bearer -> the real Metis tool list. The token
	// is minted into a variable and used only in the header; it is never
	// printed.
	valid := metisIDPToken(t, idpBin, keyPEM, metisIssuer, routeURL, metisTestScope, 600)
	resp := routeReq(t, h, "public.example.org", "/r/"+routeID+"/mcp", map[string]string{
		"Content-Type":         "application/json",
		"Authorization":        "Bearer " + valid,
		"MCP-Protocol-Version": metisProtoVerOK,
	})
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list through public route: status=%d body=%q, want 200", resp.StatusCode, body)
	}
	var out struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Result  struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("tools/list reply unparseable: %v (%q)", err, body)
	}
	if out.JSONRPC != "2.0" || out.Error != nil {
		t.Fatalf("tools/list error reply: jsonrpc=%q error=%+v body=%q", out.JSONRPC, out.Error, body)
	}
	if got := len(out.Result.Tools); got != metisExpectedToolCount {
		t.Fatalf("public route returned %d tools, want %d (names: %v)",
			got, metisExpectedToolCount, toolNames(out.Result.Tools))
	}
	t.Logf("public route returned %d tools: %v", len(out.Result.Tools), toolNames(out.Result.Tools))
	for _, tool := range out.Result.Tools {
		if !strings.HasPrefix(tool.Name, "metis_") {
			t.Errorf("tool %q is not a metis_* tool — upstream is not the real Metis", tool.Name)
		}
	}
	for _, want := range []string{"metis_send", "metis_status", "metis_terminal"} {
		found := false
		for _, tool := range out.Result.Tools {
			found = found || tool.Name == want
		}
		if !found {
			t.Errorf("real Metis tool %q missing from the public route's tool list", want)
		}
	}

	// --- Negative: a real, correctly-signed bearer minted for a
	// DIFFERENT resource must not retrieve tools. Metis validates the
	// audience against the exact resource URL from the handoff file.
	wrongAud := metisIDPToken(t, idpBin, keyPEM, metisIssuer,
		"https://evil.example/r/other/mcp", metisTestScope, 600)
	resp = routeReq(t, h, "public.example.org", "/r/"+routeID+"/mcp", map[string]string{
		"Content-Type":         "application/json",
		"Authorization":        "Bearer " + wrongAud,
		"MCP-Protocol-Version": metisProtoVerOK,
	})
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-audience bearer: status=%d body=%q, want 401", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "metis_") {
		t.Errorf("wrong-audience response leaked tool names: %q", body)
	}

	// --- Negative: no bearer at all must not retrieve tools either.
	resp = routeReq(t, h, "public.example.org", "/r/"+routeID+"/mcp", map[string]string{
		"Content-Type":         "application/json",
		"MCP-Protocol-Version": metisProtoVerOK,
	})
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing bearer: status=%d body=%q, want 401", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "metis_") {
		t.Errorf("missing-bearer response leaked tool names: %q", body)
	}

	// --- Negative (protocol contract): a valid bearer with an
	// MCP-Protocol-Version Metis does not accept is rejected with 400.
	resp = routeReq(t, h, "public.example.org", "/r/"+routeID+"/mcp", map[string]string{
		"Content-Type":         "application/json",
		"Authorization":        "Bearer " + valid,
		"MCP-Protocol-Version": "2025-06-18",
	})
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("rejected protocol version: status=%d body=%q, want 400", resp.StatusCode, body)
	}
}

func toolNames(tools []struct {
	Name string `json:"name"`
}) []string {
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = tool.Name
	}
	return names
}
