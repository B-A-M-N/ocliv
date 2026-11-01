package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFixture(t *testing.T, resource string) (*fixture, *httptest.Server) {
	t.Helper()
	f := &fixture{resource: resource, authToken: "test-token-1"}
	return f, httptest.NewServer(newMux(f))
}

func post(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp
}

func TestAuthFixtureDeniesUnauthenticatedCall(t *testing.T) {
	_, srv := testFixture(t, "https://relay.example/r/abc/mcp")
	defer srv.Close()

	for name, token := range map[string]string{"missing": "", "wrong": "nope"} {
		resp := post(t, srv.URL+"/mcp", token,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping"}}`)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s token: status=%d, want 401", name, resp.StatusCode)
		}
		if h := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(h, "Bearer ") {
			t.Fatalf("%s token: no Bearer challenge, got %q", name, h)
		}
	}
}

func TestAuthFixturePingRoundTrip(t *testing.T) {
	_, srv := testFixture(t, "https://relay.example/r/abc/mcp")
	defer srv.Close()

	call := func(body string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token-1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	init := call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}`)
	if res, _ := init["result"].(map[string]any); res == nil || res["protocolVersion"] != "2026-07-28" {
		t.Fatalf("initialize: %v", init)
	}

	list := call(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	tools, _ := list["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "ping" {
		t.Fatalf("tools/list: %v", list)
	}

	bad := call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec"}}`)
	if bad["error"] == nil {
		t.Fatalf("unknown tool accepted: %v", bad)
	}
	args := call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ping","arguments":{"x":1}}}`)
	if args["error"] == nil {
		t.Fatalf("ping with args accepted: %v", args)
	}
	ok := call(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ping"}}`)
	content, _ := ok["result"].(map[string]any)["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["text"] != "pong:ocliv-auth-fixture-1" {
		t.Fatalf("ping: %v", ok)
	}

	notifReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	notifReq.Header.Set("Authorization", "Bearer test-token-1")
	notifResp, err := http.DefaultClient.Do(notifReq)
	if err != nil {
		t.Fatal(err)
	}
	notifResp.Body.Close()
	if notifResp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification: status=%d, want 202", notifResp.StatusCode)
	}
}

func TestAuthFixtureMetadataAdvertisesBoundResource(t *testing.T) {
	_, srv := testFixture(t, "https://relay.example/r/abc/mcp")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct {
		Resource string `json:"resource"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Resource != "https://relay.example/r/abc/mcp" {
		t.Fatalf("resource=%q, want exact bound URL", doc.Resource)
	}
}

func TestAuthFixtureTokenFileRevocation(t *testing.T) {
	tf := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tf, []byte("live-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{resource: "https://relay.example/r/abc/mcp", tokenFile: tf}
	srv := httptest.NewServer(newMux(f))
	defer srv.Close()

	good := post(t, srv.URL+"/mcp", "live-token",
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if good.StatusCode != http.StatusOK {
		t.Fatalf("live token: status=%d, want 200", good.StatusCode)
	}

	// Rotate the file: old token must stop working without restart.
	if err := os.WriteFile(tf, []byte("rotated-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := post(t, srv.URL+"/mcp", "live-token",
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if stale.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token: status=%d, want 401", stale.StatusCode)
	}
}

func TestAuthFixtureBindingFileRebindsWithoutRestart(t *testing.T) {
	bf := filepath.Join(t.TempDir(), "resource.url")
	if err := os.WriteFile(bf, []byte("http://127.0.0.1:18766/mcp"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{resource: "http://127.0.0.1:18766/mcp", resourceFile: bf, authToken: "test-token-1"}
	srv := httptest.NewServer(newMux(f))
	defer srv.Close()

	metadata := func() string {
		t.Helper()
		resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource/mcp")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc struct {
			Resource string `json:"resource"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc.Resource
	}

	if got := metadata(); got != "http://127.0.0.1:18766/mcp" {
		t.Fatalf("initial resource=%q", got)
	}

	// Publisher publishes: atomically swaps the binding to the public URL.
	tmp := bf + ".tmp"
	if err := os.WriteFile(tmp, []byte("https://relay.example/r/route1/mcp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, bf); err != nil {
		t.Fatal(err)
	}
	if got := metadata(); got != "https://relay.example/r/route1/mcp" {
		t.Fatalf("after publisher binding, resource=%q, want public route URL", got)
	}
}

func TestAuthFixtureRejectsUnsupportedVersion(t *testing.T) {
	_, srv := testFixture(t, "https://relay.example/r/abc/mcp")
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`))
	req.Header.Set("Authorization", "Bearer test-token-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["error"] == nil {
		t.Fatalf("unsupported version accepted: %v", out)
	}
}
