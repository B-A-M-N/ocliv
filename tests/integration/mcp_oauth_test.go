package integration

// Upstream OAuth enforcement end-to-end (P0-D). Ocliv's upstream-oauth
// profile deliberately delegates authorization to the local MCP
// resource server: the relay forwards the application bearer
// byte-identical and never executes tools itself. This file proves,
// through the REAL relay → agent → upstream path, that an
// OAuth-enforcing upstream admits exactly the authorized call and
// that every denied call executes zero tools.
//
// Test token scheme (local-only, never a production format):
// the bearer value is "aud=<aud>&scope=<scope>&exp=<unix>". The
// upstream enforces exact audience match, required scope membership,
// and expiry against its clock. Provider-issued tokens, real client
// flows, and ChatGPT registration remain BLOCKED on external
// infrastructure and are NOT claimed here.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ocliv/internal/config"
)

// oauthUpstream is a minimal MCP resource server: it serves the
// protected-resource metadata document and enforces bearer claims on
// the tool endpoint, counting actual tool executions. The audience is
// set after route creation (the route URL is minted by the relay),
// modeling the publisher binding its resource server to the
// advertised URL.
type oauthUpstream struct {
	audience atomic.Value // string: exact expected resource URL
	execs    atomic.Int64 // tool executions: increments only past auth
	seenAuth atomic.Value // last Authorization header observed
	srv      *httptest.Server
}

func startOAuthUpstream(t *testing.T) *oauthUpstream {
	t.Helper()
	up := &oauthUpstream{}
	up.audience.Store("")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"resource":%q}`, up.audience.Load().(string))
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		up.seenAuth.Store(auth)
		if !up.authorized(auth) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		up.execs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":["demo"]}}`))
	})
	up.srv = httptest.NewServer(mux)
	t.Cleanup(up.srv.Close)
	return up
}

// authorized enforces the three upstream checks: exact audience,
// required scope, unexpired token. Anything else denies with zero
// execution (the counter increments only past this gate).
func (up *oauthUpstream) authorized(auth string) bool {
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tok == "" {
		return false
	}
	claims := map[string]string{}
	for _, part := range strings.Split(tok, "&") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return false
		}
		claims[k] = v
	}
	if claims["aud"] != up.audience.Load().(string) || claims["aud"] == "" {
		return false
	}
	scopeOK := false
	for _, s := range strings.Split(claims["scope"], " ") {
		if s == "mcp:tools" {
			scopeOK = true
		}
	}
	if !scopeOK {
		return false
	}
	exp, err := strconv.ParseInt(claims["exp"], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return true
}

// oauthHarness attaches an agent to the OAuth upstream and publishes
// an activated upstream-oauth route for it, binding the upstream's
// expected audience to the advertised route URL (the publisher's
// resource-server configuration step).
func oauthHarness(t *testing.T) (*harness, *oauthUpstream, string) {
	t.Helper()
	up := startOAuthUpstream(t)
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	t.Cleanup(func() { h.db.Close() })
	t.Cleanup(h.relaySrv.Close)
	h.startAgentOpts(t, portOfUpstream(t, up.srv.URL), config.Agent{AccessMode: "mcp_upstream_oauth"})
	code, rid, url, _ := mgmtRouteCreate(t, h, "upstream-oauth")
	if code != http.StatusOK {
		t.Fatalf("route create status=%d", code)
	}
	up.audience.Store(url)
	mgmtRouteActivate(t, h, rid)
	return h, up, rid
}

func portOfUpstream(t *testing.T, rawURL string) int {
	t.Helper()
	rest, ok := strings.CutPrefix(rawURL, "http://127.0.0.1:")
	if !ok {
		t.Fatalf("unexpected upstream url %q", rawURL)
	}
	var port int
	if _, err := fmt.Sscanf(rest, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return port
}

func oauthCall(t *testing.T, h *harness, rid, bearer string) (int, string) {
	t.Helper()
	headers := map[string]string{"Content-Type": "application/json"}
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	resp := routeReq(t, h, "public.example.org", "/r/"+rid+"/mcp", headers)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	return resp.StatusCode, string(body)
}

// TestUpstreamOAuthAdmitsAuthorizedCall: the one authorized shape —
// exact audience, required scope, live token — executes exactly once,
// and the bearer arrives byte-identical for upstream validation.
func TestUpstreamOAuthAdmitsAuthorizedCall(t *testing.T) {
	h, up, rid := oauthHarness(t)
	aud := up.audience.Load().(string)
	good := fmt.Sprintf("aud=%s&scope=mcp:tools&exp=%d", aud, time.Now().Add(time.Hour).Unix())
	before := up.execs.Load()
	code, _ := oauthCall(t, h, rid, good)
	if code != http.StatusOK {
		t.Fatalf("authorized call status=%d, want 200", code)
	}
	if got := up.execs.Load() - before; got != 1 {
		t.Fatalf("authorized call executed %d tools, want 1", got)
	}
	if seen, _ := up.seenAuth.Load().(string); seen != "Bearer "+good {
		t.Fatalf("bearer corrupted in transit: %q", seen)
	}
}

// TestUpstreamOAuthDeniesEverythingElse: each unauthorized shape is
// denied by the upstream with ZERO tool executions — the relay
// forwards the bearer untouched, and the resource server alone
// decides. The oracle is the execution counter, not the status code.
func TestUpstreamOAuthDeniesEverythingElse(t *testing.T) {
	h, up, rid := oauthHarness(t)
	aud := up.audience.Load().(string)
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()
	cases := map[string]string{
		"missing bearer":     "",
		"malformed":          "not-a-claims-string",
		"wrong audience":     fmt.Sprintf("aud=https://evil.example/r/x/mcp&scope=mcp:tools&exp=%d", future),
		"empty audience":     fmt.Sprintf("aud=&scope=mcp:tools&exp=%d", future),
		"insufficient scope": fmt.Sprintf("aud=%s&scope=mcp:read&exp=%d", aud, future),
		"empty scope":        fmt.Sprintf("aud=%s&scope=&exp=%d", aud, future),
		"expired":            fmt.Sprintf("aud=%s&scope=mcp:tools&exp=%d", aud, past),
		"bad expiry":         fmt.Sprintf("aud=%s&scope=mcp:tools&exp=soon", aud),
	}
	for name, bearer := range cases {
		before := up.execs.Load()
		code, _ := oauthCall(t, h, rid, bearer)
		if code != http.StatusUnauthorized {
			t.Errorf("%s: status=%d, want 401", name, code)
		}
		if got := up.execs.Load() - before; got != 0 {
			t.Errorf("%s: executed %d tools, want 0", name, got)
		}
	}
}
