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

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"ocliv/internal/apperr"
	mcpadapter "ocliv/internal/mcp"
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
				if !out.Verified || out.Auth != "AUTH_REQUIRED" || doctorProtocolExit("mcp_managed_oauth", out.Verified) != apperr.ExitOK {
					t.Fatalf("managed protocol not verified: %+v", out)
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
