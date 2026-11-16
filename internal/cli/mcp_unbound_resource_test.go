package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// metisLikeUnboundServer stands in for Metis `mcp serve-http` in
// file-resource mode (mcp_http.go): while the publisher's resource-file
// handoff (METIS_MCP_RESOURCE_FILE, written by Ocliv AFTER route
// registration) is absent, BOTH /mcp and the discovery path answer
// "resource not configured" (503). Once the file appears the /mcp path
// answers an OAuth bearer challenge (401 + WWW-Authenticate), exactly as
// Metis does.
func metisLikeUnboundServer(t *testing.T, resourcePath string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(resourcePath)
		if err != nil || strings.TrimSpace(string(b)) == "" {
			http.Error(w, "resource not configured", http.StatusServiceUnavailable)
			return
		}
		if strings.Contains(r.URL.Path, "oauth-protected-resource") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"resource":%q}`, strings.TrimSpace(string(b)))
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource="`+strings.TrimSpace(string(b))+`", error="invalid_token"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
}

// Resource-file-bound servers may report their narrow pre-handoff signal,
// but that is not protocol evidence. It permits the handoff step only;
// tools/list and authorization checks must pass afterward and before route
// activation.
func TestProbeUnboundResourceServerOnlyPassesHandoffPreflight(t *testing.T) {
	dir := t.TempDir()
	resourceFile := dir + "/route.txt"
	srv := metisLikeUnboundServer(t, resourceFile)
	defer srv.Close()

	// Step 1 of runMCPPublish happens with the handoff unwritten.
	target := probeTarget(srv)
	out := runMCPProbe(target, "mcp_upstream_oauth")

	cfg := mcpPublishConfig{auth: "upstream-oauth", resourceFile: resourceFile}
	if !publishInitialProbeOK(out, cfg) {
		t.Fatalf("exact unbound handoff signal did not pass initial preflight: %+v", out)
	}
	if !out.UnboundHandoff || out.Verified {
		t.Fatalf("preflight must report handoff-only, not protocol validity: %+v", out)
	}
	if publishLocalProbeOK(out, "upstream-oauth", false) || publishLocalProbeOK(out, "upstream-oauth", true) {
		t.Fatal("unbound signal alone must never satisfy the post-handoff protocol gate")
	}
	if out.Auth != "AUTH_REQUIRED" {
		t.Fatalf("auth=%q, want AUTH_REQUIRED", out.Auth)
	}
	if !strings.Contains(strings.ToLower(out.Summary), "resource not configured") {
		t.Fatalf("summary=%q should name the resource-not-configured state", out.Summary)
	}
}

// The anonymous fixture must never be waved through by a 503: its
// profile cannot grow an auth surface, so an unbound/authority-demanding
// server stays a broken launch for it. This preserves the existing
// fixture contract for 503 exactly as it holds for 401/403.
func TestProbeUnboundServerStillFailsAnonymousFixture(t *testing.T) {
	dir := t.TempDir()
	srv := metisLikeUnboundServer(t, dir+"/route.txt")
	defer srv.Close()
	out := runMCPProbe(probeTarget(srv), "mcp_anonymous_fixture")
	if out.Verified || publishLocalProbeOK(out, "fixture-anonymous", false) {
		t.Fatalf("anonymous fixture must not publish an unbound server: verified=%v auth=%q summary=%q", out.Verified, out.Auth, out.Summary)
	}
	// The 401 challenge (once bound) still maps to AUTH_REQUIRED for
	// upstream-oauth and BROKEN for the fixture — unchanged behavior.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
		http.Error(w, "bearer required", http.StatusUnauthorized)
	}))
	defer srv2.Close()
	oa := runMCPProbe(probeTarget(srv2), "mcp_upstream_oauth")
	if oa.Auth != "AUTH_REQUIRED" {
		t.Fatalf("401 upstream-oauth auth=%q, want AUTH_REQUIRED", oa.Auth)
	}
	fx := runMCPProbe(probeTarget(srv2), "mcp_anonymous_fixture")
	if !strings.Contains(fx.Summary, "broken") {
		t.Fatalf("401 fixture summary=%q, want broken verdict", fx.Summary)
	}
}

// A 503 that is NOT the unbound-handoff signal (an overloaded,
// unhealthy or otherwise broken upstream) must NOT be read as
// authenticating presence. Only the specific "resource not
// configured" body qualifies; a bare 503 stays a failed local
// target, so publish never builds a tunnel and route for a broken
// upstream.
func TestProbeRejects503WithoutUnboundHandoffSignal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable: upstream overloaded", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	out := runMCPProbe(probeTarget(srv), "mcp_upstream_oauth")
	if out.Auth == "AUTH_REQUIRED" && publishLocalProbeOK(out, "upstream-oauth", false) {
		t.Fatalf("a non-handoff 503 must not be accepted as authenticating presence: auth=%q summary=%q",
			out.Auth, out.Summary)
	}
}
