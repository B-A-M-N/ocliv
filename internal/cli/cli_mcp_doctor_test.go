package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	srv, _ := mcpProbeFixture(t, map[string]string{
		"tools/list": `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28","tools":[{"name":"ping"}]}}`,
	})
	defer srv.Close()
	oauth := runMCPProbe(probeTarget(srv), "mcp_upstream_oauth")
	if !oauth.Verified || oauth.Auth != "AUTH_UNVERIFIED" || oauth.Protocol != "2026-07-28" {
		t.Fatalf("modern outcome: %+v", oauth)
	}
	fixture := runMCPProbe(probeTarget(srv), "mcp_anonymous_fixture")
	if !fixture.Verified || fixture.Auth != "AUTH_NONE" {
		t.Fatalf("modern fixture outcome: %+v", fixture)
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
