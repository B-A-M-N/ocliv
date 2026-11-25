package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	mcpadapter "github.com/B-A-M-N/ocliv/internal/mcp"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Publication tiers (P1-D) must never report active unless the relay
// says active, the lease is ACTIVE, the attachment is live, and the
// local probe passed. Anything else degrades honestly.
func TestDoctorPublicationTier(t *testing.T) {
	for _, tc := range []struct {
		name        string
		pub, lease  string
		live, local bool
		want        string
	}{
		{"active", "active", "ACTIVE", true, true, "active"},
		{"revoked wins", "revoked", "ACTIVE", true, true, "revoked"},
		{"expired lease", "active", "EXPIRED", false, false, "expired"},
		{"active lease no attachment", "active", "ACTIVE", false, true, "offline"},
		{"attached but local down", "active", "ACTIVE", true, false, "degraded"},
		{"closed lease", "active", "CLOSED", false, true, "offline"},
		{"unknown state", "active", "RECONNECTING", false, false, "offline"},
		{"unknown pubstate", "bogus", "ACTIVE", true, true, "active"},
	} {
		if got := doctorPublicationTier(tc.pub, tc.lease, tc.live, tc.local); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestManagedMCPDoctorUsesAndDeletesStreamableSession(t *testing.T) {
	script := "while IFS= read -r req; do\n" +
		"id=$(printf '%s' \"$req\" | sed -n 's/.*\"id\":\"\\([^\"]*\\)\".*/\\1/p')\n" +
		"case \"$req\" in\n" +
		"  *'\"method\":\"initialize\"'*) printf '{\"jsonrpc\":\"2.0\",\"id\":\"%s\",\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"probe\",\"version\":\"1\"}}}\\n' \"$id\" ;;\n" +
		"  *'\"method\":\"tools/list\"'*) printf '{\"jsonrpc\":\"2.0\",\"id\":\"%s\",\"result\":{\"tools\":[]}}\\n' \"$id\" ;;\n" +
		"esac\ndone"
	a, err := mcpadapter.New(mcpadapter.Options{
		Command: "sh", Args: []string{"-c", script}, MultiClientSessions: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	out := runMCPProbeWithBearer(a.Addr().String(), "mcp_managed_oauth", "")
	if !out.Verified {
		t.Fatalf("managed stdio adapter failed MCP probe: %+v", out)
	}
	if got := a.SessionCount(); got != 0 {
		t.Fatalf("doctor probe leaked %d Streamable HTTP sessions", got)
	}
}

// The staged probe must validate envelopes, not just shapes: id echo,
// result/error exclusivity, and a negotiated protocol version.
func TestProbeValidatesEnvelopes(t *testing.T) {
	cases := map[string]struct {
		replies map[string]string
		want    string
	}{
		"wrong id echo": {
			map[string]string{
				"initialize":                `{"jsonrpc":"2.0","id":99,"result":{"protocolVersion":"2024-11-05"}}`,
				"notifications/initialized": `{}`,
				"tools/list":                `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`,
			},
			"reply id",
		},
		"result and error together": {
			map[string]string{
				"initialize":                `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32600,"message":"x"}}`,
				"notifications/initialized": `{}`,
				"tools/list":                `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`,
			},
			"exactly one of result/error",
		},
		"missing protocol version": {
			map[string]string{
				"initialize":                `{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"fx"}}}`,
				"notifications/initialized": `{}`,
				"tools/list":                `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`,
			},
			"initialize invalid",
		},
		"rejected notification": {
			map[string]string{
				"initialize": `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`,
				"tools/list": `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`,
			},
			"initialized notification rejected",
		},
	}
	for name, tc := range cases {
		srv, _ := mcpProbeFixture(t, tc.replies)
		status, verified := probeMCPProtocol(probeTarget(srv), "mcp_upstream_oauth")
		srv.Close()
		if verified {
			t.Errorf("%s: verified, want rejection: %q", name, status)
		} else if !strings.Contains(status, tc.want) {
			t.Errorf("%s: status %q, want %q", name, status, tc.want)
		}
	}
}

// SSE-wrapped JSON-RPC replies are decoded, not rejected as non-JSON;
// a stream with no data is a protocol failure.
func TestProbeDecodesSSEResponses(t *testing.T) {
	sse := func(raw string) (*http.Response, []byte) {
		return &http.Response{StatusCode: 200,
				Header: http.Header{"Content-Type": []string{"text/event-stream"}}},
			[]byte(raw)
	}
	out, err := decodeJSONRPC(sse("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n"))
	if err != nil {
		t.Fatalf("SSE decode failed: %v", err)
	}
	if v, err := validateEnvelope(out, 7); err != nil || v != "" {
		t.Fatalf("SSE envelope invalid: v=%q err=%v", v, err)
	}
	if _, err := decodeJSONRPC(sse(": keep-alive\n\n")); err == nil {
		t.Fatal("SSE stream without data accepted")
	}
}

func TestProbeSSEReturnsBeforeStreamEOF(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	var resp *http.Response
	var srv *httptest.Server
	defer func() {
		releaseOnce.Do(func() { close(release) })
		if resp != nil {
			_ = resp.Body.Close()
		}
		if srv != nil {
			srv.Close()
		}
	}()
	var flushed atomic.Bool
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n\n")
		flushed.Store(true)
		w.(http.Flusher).Flush()
		<-release // keep the HTTP body open after the matching event
	}))
	var err error
	resp, err = http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var got []byte
	var readErr error
	go func() { got, readErr = readMCPProbeBody(resp, "7"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		releaseOnce.Do(func() { close(release) })
		_ = resp.Body.Close()
		t.Fatal("SSE probe waited for connection EOF after the matching event")
	}
	if !flushed.Load() || readErr != nil || string(got) != `{"jsonrpc":"2.0","id":7,"result":{}}` {
		t.Fatalf("flushed=%v body=%q err=%v", flushed.Load(), got, readErr)
	}
	releaseOnce.Do(func() { close(release) })
}

func TestManagedDoctorRequiresMCPProtocol(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{name: "valid tools list", valid: true},
		{name: "GET works but POST is missing"},
		{name: "HTML page"},
		{name: "malformed JSON-RPC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, "<html>alive</html>")
					return
				}
				if !tc.valid {
					switch tc.name {
					case "GET works but POST is missing":
						http.NotFound(w, r)
					case "HTML page":
						_, _ = io.WriteString(w, "<html>not MCP</html>")
					case "malformed JSON-RPC":
						_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":`)
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
			}))
			defer srv.Close()
			out := runMCPProbe(probeTarget(srv), "mcp_managed_oauth")
			if tc.valid {
				if !out.Verified || out.Auth != "RELAY_MANAGED_OAUTH" || out.AuthEvidence.Mode != "RELAY_MANAGED_OAUTH" || out.AuthEvidence.LocalAccess != "VERIFIED" || doctorProtocolExit("mcp_managed_oauth", out.Verified) != apperr.ExitOK {
					t.Fatalf("managed protocol not verified: %+v", out)
				}
				if line := doctorAuthLine("mcp_managed_oauth", out.Auth); strings.Contains(line, "configure the upstream OAuth client") {
					t.Fatalf("managed OAuth doctor line wrongly suggests upstream OAuth client: %q", line)
				}
			} else if out.Verified || doctorProtocolExit("mcp_managed_oauth", out.Verified) == apperr.ExitOK {
				t.Fatalf("non-MCP endpoint passed managed protocol check: %+v", out)
			}
		})
	}
}

// Authentication is a separate facet: a 401 is AUTH_REQUIRED for
// upstream-oauth (configure the client), but BROKEN for the anonymous
// fixture (which must never demand auth). Neither verifies.
func TestProbeSeparatesAuthRequiredFromBroken(t *testing.T) {
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://idp.test/.well-known/oauth-authorization-server"`)
		http.Error(w, "bearer required", http.StatusUnauthorized)
	}))
	defer deny.Close()
	oauth := runMCPProbe(probeTarget(deny), "mcp_upstream_oauth")
	if oauth.Verified || oauth.Auth != "AUTH_REQUIRED" {
		t.Fatalf("oauth 401: verified=%v auth=%s summary=%q", oauth.Verified, oauth.Auth, oauth.Summary)
	}
	if !strings.Contains(oauth.Summary, "auth: required") {
		t.Fatalf("oauth 401 summary hides the auth stage: %q", oauth.Summary)
	}
	fixture := runMCPProbe(probeTarget(deny), "mcp_anonymous_fixture")
	if fixture.Verified || !strings.Contains(fixture.Summary, "broken") {
		t.Fatalf("fixture 401: verified=%v summary=%q", fixture.Verified, fixture.Summary)
	}
}

// A modern (2026-07-28, stateless) server answers versioned tools/list
// with an id-echoed reply and no handshake; the probe must verify it on
// the modern path and report the negotiated revision.
func TestProbeVerifiesModernStatelessServer(t *testing.T) {
	var badRequest string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Method string `json:"method"`
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			badRequest = "invalid JSON: " + err.Error()
		} else {
			var protocolVersion string
			var capabilities map[string]any
			_ = json.Unmarshal(in.Params.Meta["io.modelcontextprotocol/protocolVersion"], &protocolVersion)
			_ = json.Unmarshal(in.Params.Meta["io.modelcontextprotocol/clientCapabilities"], &capabilities)
			if in.Method != "tools/list" || r.Header.Get("MCP-Protocol-Version") != "2026-07-28" || r.Header.Get("MCP-Method") != "tools/list" || protocolVersion != "2026-07-28" || capabilities == nil {
				badRequest = "missing modern MCP request metadata"
			}
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28","tools":[{"name":"ping"}]}}`))
	}))
	defer srv.Close()
	oauth := runMCPProbe(probeTarget(srv), "mcp_upstream_oauth")
	if badRequest != "" {
		t.Fatal(badRequest)
	}
	if !oauth.Verified || oauth.Auth != "AUTH_UNVERIFIED" || oauth.Protocol != "2026-07-28" {
		t.Fatalf("modern outcome: %+v", oauth)
	}
	fixture := runMCPProbe(probeTarget(srv), "mcp_anonymous_fixture")
	if !fixture.Verified || fixture.Auth != "AUTH_NONE" {
		t.Fatalf("modern fixture outcome: %+v", fixture)
	}
}

// Run the modern probe against the reference Go SDK's stateless HTTP
// handler. The SDK itself validates the 2026 request metadata and headers.
func TestProbeVerifiesModernGoSDKServer(t *testing.T) {
	server := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "modern-sdk", Version: "test"}, &sdkmcp.ServerOptions{
		SupportedProtocolVersions: []string{"2026-07-28"},
	})
	handler := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server { return server }, &sdkmcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	out := runMCPProbe(probeTarget(srv), "mcp_upstream_oauth")
	if !out.Verified || out.Protocol != "2026-07-28" {
		t.Fatalf("reference SDK modern outcome: %+v", out)
	}
}

// A reference SDK server restricted to the legacy initialize protocol
// rejects the modern stateless request and must pass through the separate
// initialize/initialized/tools-list path.
func TestProbeVerifiesLegacyOnlyGoSDKServer(t *testing.T) {
	server := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "legacy-sdk", Version: "test"}, &sdkmcp.ServerOptions{
		SupportedProtocolVersions: []string{"2024-11-05"},
	})
	handler := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server { return server }, &sdkmcp.StreamableHTTPOptions{
		JSONResponse: true,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	out := runMCPProbe(probeTarget(srv), "mcp_upstream_oauth")
	if !out.Verified || out.Protocol != "2024-11-05" {
		t.Fatalf("reference SDK legacy outcome: %+v", out)
	}
}

// Full-handshake auth facets: fixture servers are AUTH_NONE, answering
// oauth servers are AUTH_UNVERIFIED (usability proven, enforcement not).
func TestProbeAuthFacets(t *testing.T) {
	srv, _ := mcpProbeFixture(t, map[string]string{
		"initialize":                `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`,
		"notifications/initialized": `{}`,
		"tools/list":                `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`,
	})
	defer srv.Close()
	oauth := runMCPProbe(probeTarget(srv), "mcp_upstream_oauth")
	if !oauth.Verified || oauth.Auth != "AUTH_UNVERIFIED" || oauth.Protocol != "2024-11-05" {
		t.Fatalf("oauth outcome: %+v", oauth)
	}
	fixture := runMCPProbe(probeTarget(srv), "mcp_anonymous_fixture")
	if !fixture.Verified || fixture.Auth != "AUTH_NONE" {
		t.Fatalf("fixture outcome: %+v", fixture)
	}
	if got := doctorAuthLine("mcp_upstream_oauth", "AUTH_UNVERIFIED"); !strings.Contains(got, "NOT proven") {
		t.Fatalf("oauth auth line hides the gap: %q", got)
	}
}

// OCL-001: Managed OAuth diagnostics must never recommend configuring an
// upstream OAuth client on either modern or legacy MCP probe paths.
func TestManagedOAuthDiagnosticsConsistentAcrossModernAndLegacy(t *testing.T) {
	modernSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28","tools":[{"name":"ping"}]}}`)
	}))
	defer modernSrv.Close()
	legacySrv, _ := mcpProbeFixture(t, map[string]string{
		"initialize":                `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`,
		"notifications/initialized": `{}`,
		"tools/list":                `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"ping"}]}}`,
	})
	defer legacySrv.Close()

	for name, srv := range map[string]*httptest.Server{"modern": modernSrv, "legacy": legacySrv} {
		out := runMCPProbe(probeTarget(srv), "mcp_managed_oauth")
		if !out.Verified {
			t.Fatalf("%s: expected verified, got %+v", name, out)
		}
		if out.Auth != "RELAY_MANAGED_OAUTH" {
			t.Fatalf("%s: auth=%q, want RELAY_MANAGED_OAUTH", name, out.Auth)
		}
		if out.AuthEvidence.Mode != "RELAY_MANAGED_OAUTH" || out.AuthEvidence.LocalAccess != "VERIFIED" ||
			out.AuthEvidence.PublicEnforcement != "NOT_TESTED" || out.AuthEvidence.AuthenticatedPublicMCP != "NOT_TESTED" {
			t.Fatalf("%s: unexpected AuthEvidence: %+v", name, out.AuthEvidence)
		}
		line := doctorAuthLine("mcp_managed_oauth", out.Auth)
		if strings.Contains(line, "configure the upstream OAuth client") || strings.Contains(line, "server demands bearer") {
			t.Fatalf("%s: misleading managed auth line: %q", name, line)
		}
	}
}

// OCL-003: Authenticated public MCP probe must preserve HTTPS scheme, exact
// path-routed URL, nonstandard port, session DELETE URL, SSE decoding, and
// redact bearer tokens on failure without following redirects.
func TestMCPProbeConfigCanonicalEndpoints(t *testing.T) {
	const secretTok = "super-secret-bearer-token-xyz"
	var gotPaths []string
	var gotMethods []string
	var gotAuthHeaders []string
	var mu sync.Mutex

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPaths = append(gotPaths, r.URL.Path)
		gotMethods = append(gotMethods, r.Method)
		gotAuthHeaders = append(gotAuthHeaders, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.URL.Path != "/r/route-abc/mcp" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+secretTok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Mcp-Session-Id", "sess-https-1")
		switch req.Method {
		case "initialize":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}\n\n")
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if r.Header.Get("MCP-Protocol-Version") == "2026-07-28" {
				// Force fallback to legacy path so session creation + DELETE are exercised too.
				http.Error(w, "legacy only", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"echo\"}]}}\n\n")
		}
	}))
	defer tlsSrv.Close()

	ep, err := localMCPEndpoint(tlsSrv.URL + "/r/route-abc/mcp")
	if err != nil {
		t.Fatalf("localMCPEndpoint: %v", err)
	}
	out := runMCPProbeWithConfig(MCPProbeConfig{
		Endpoint:    ep,
		AuthMode:    "mcp_managed_oauth",
		BearerToken: secretTok,
		Client:      wrapNoRedirectClient(tlsSrv.Client()),
		IsPublic:    true,
	})
	if !out.Verified || out.Auth != "RELAY_MANAGED_OAUTH" || out.AuthEvidence.AuthenticatedPublicMCP != "VERIFIED" {
		t.Fatalf("HTTPS path-routed probe failed: %+v", out)
	}
	if strings.Contains(out.Summary, secretTok) {
		t.Fatalf("bearer token leaked into summary: %q", out.Summary)
	}
	mu.Lock()
	sawDelete := false
	for i, m := range gotMethods {
		if gotPaths[i] != "/r/route-abc/mcp" {
			t.Fatalf("unexpected request path %q (want /r/route-abc/mcp)", gotPaths[i])
		}
		if m == http.MethodDelete {
			sawDelete = true
			if gotAuthHeaders[i] != "Bearer "+secretTok {
				t.Fatalf("DELETE session termination missing bearer auth")
			}
		}
	}
	mu.Unlock()
	if !sawDelete {
		t.Fatal("expected session DELETE on exact canonical path")
	}

	// Verify IPv6 loopback target construction preserves brackets and port.
	v6ep, err := localMCPEndpoint("[::1]:18777")
	if err != nil || v6ep.String() != "http://[::1]:18777/mcp" {
		t.Fatalf("IPv6 endpoint = %v, err=%v", v6ep, err)
	}

	// Verify redirect never receives forwarded bearer credentials.
	var evilGotAuth bool
	evilSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			evilGotAuth = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer evilSrv.Close()
	redirSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evilSrv.URL+"/steal", http.StatusFound)
	}))
	defer redirSrv.Close()
	redirEP, _ := localMCPEndpoint(redirSrv.URL + "/r/r1/mcp")
	redirOut := runMCPProbeWithConfig(MCPProbeConfig{
		Endpoint:    redirEP,
		AuthMode:    "mcp_managed_oauth",
		BearerToken: secretTok,
		Client:      wrapNoRedirectClient(redirSrv.Client()),
		IsPublic:    true,
	})
	if redirOut.Verified {
		t.Fatalf("redirect probe must fail, got %+v", redirOut)
	}
	if evilGotAuth {
		t.Fatal("bearer credential was forwarded to redirected origin!")
	}
	if strings.Contains(redirOut.Summary, secretTok) {
		t.Fatalf("bearer token leaked in redirect failure summary: %q", redirOut.Summary)
	}
}
