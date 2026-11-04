package cli

// Parse and validation tests for `mcp publish` / `mcp serve` (P1). These
// pin the operator contract: explicit auth, loopback-only local targets,
// exactly /mcp, no --public, and argv-vector child commands.

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
)

func TestParseMCPPublishLocal(t *testing.T) {
	// Both `--flag value` (target UX) and `--flag=value` (mcp-family
	// style) must parse identically.
	for _, argv := range [][]string{
		{"--local", "http://127.0.0.1:8765/mcp", "--auth", "upstream-oauth", "--name", "dev-tools", "--ttl", "2h"},
		{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--name=dev-tools", "--ttl=2h"},
	} {
		c, code := parseMCPPublish(argv, false)
		if code != 0 {
			t.Fatalf("valid publish %q rejected: code=%d", argv, code)
		}
		if c.serve || c.stdio || c.localURL != "http://127.0.0.1:8765/mcp" || c.auth != "upstream-oauth" || c.name != "dev-tools" || c.ttl != "2h" {
			t.Fatalf("publish config misparsed: %+v", c)
		}
	}
}

// Anonymous fixtures cannot be published (P0-F): the fixture-anonymous
// profile cannot bound an arbitrary local server, so it must never back
// a public route. Local-only lifecycle (serve) and diagnostics keep
// accepting it; publish requires upstream-oauth.
func TestParseMCPPublishFixtureAnonymousRefused(t *testing.T) {
	pub := []string{"--local=http://127.0.0.1:8765/mcp", "--auth=fixture-anonymous"}
	if _, code := parseMCPPublish(pub, false); code == 0 {
		t.Error("publish --auth fixture-anonymous accepted, want rejection")
	}
	srv := []string{"--local=http://127.0.0.1:8765/mcp", "--auth=fixture-anonymous"}
	if _, code := parseMCPPublish(srv, true); code != 0 {
		t.Errorf("serve --auth fixture-anonymous rejected, want local-only acceptance (code %d)", code)
	}
	oauth := []string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth"}
	if _, code := parseMCPPublish(oauth, false); code != 0 {
		t.Errorf("publish --auth upstream-oauth rejected (code %d)", code)
	}
}

// --strict-discovery constrains publish only: accepted in publish
// mode, rejected in serve mode (no route, no discovery). Production
// publication is strict by default (P0-B): unproven bindings abort
// unless explicit dev-only --dev-allow-unverified-discovery is set.
func TestParseMCPPublishStrictDiscovery(t *testing.T) {
	pub := []string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--strict-discovery"}
	c, code := parseMCPPublish(pub, false)
	if code != 0 || !c.strictDiscovery {
		t.Fatalf("publish --strict-discovery rejected or dropped: %+v code=%d", c, code)
	}
	plain := []string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth"}
	c, code = parseMCPPublish(plain, false)
	if code != 0 || c.devAllowUnverified {
		t.Fatalf("default must stay strict (no dev opt-out): %+v code=%d", c, code)
	}
	dev := []string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--dev-allow-unverified-discovery"}
	c, code = parseMCPPublish(dev, false)
	if code != 0 || !c.devAllowUnverified {
		t.Fatalf("publish --dev-allow-unverified-discovery rejected or dropped: %+v code=%d", c, code)
	}
	if _, code := parseMCPPublish(pub, true); code == 0 {
		t.Fatal("serve --strict-discovery accepted, want rejection")
	}
	if _, code := parseMCPPublish(dev, true); code == 0 {
		t.Fatal("serve --dev-allow-unverified-discovery accepted, want rejection")
	}
	for _, tc := range []struct {
		name  string
		cfg   mcpPublishConfig
		err   error
		fatal bool
	}{
		{"nil is fine", mcpPublishConfig{}, nil, false},
		{"unreachable default aborts", mcpPublishConfig{auth: "upstream-oauth"}, errDiscoveryUnreachable, true},
		{"unreachable strict aborts", mcpPublishConfig{auth: "upstream-oauth", strictDiscovery: true}, errDiscoveryUnreachable, true},
		{"unreachable dev warns", mcpPublishConfig{auth: "upstream-oauth", devAllowUnverified: true}, errDiscoveryUnreachable, false},
		{"invalid default aborts", mcpPublishConfig{auth: "upstream-oauth"}, errors.New("resource mismatch"), true},
		{"invalid strict aborts", mcpPublishConfig{auth: "upstream-oauth", strictDiscovery: true}, errors.New("resource mismatch"), true},
		{"invalid dev still aborts", mcpPublishConfig{auth: "upstream-oauth", devAllowUnverified: true}, errors.New("resource mismatch"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := discoveryFailureFatal(tc.cfg, tc.err); got != tc.fatal {
				t.Fatalf("discoveryFailureFatal = %v, want %v", got, tc.fatal)
			}
		})
	}
}

func TestParseMCPPublishResourceFile(t *testing.T) {
	pub := []string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--resource-file", "/tmp/x.resource"}
	c, code := parseMCPPublish(pub, false)
	if code != 0 || c.resourceFile != "/tmp/x.resource" {
		t.Fatalf("space form dropped: %+v code=%d", c, code)
	}
	pub = []string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--resource-file=/tmp/y.resource"}
	c, code = parseMCPPublish(pub, false)
	if code != 0 || c.resourceFile != "/tmp/y.resource" {
		t.Fatalf("equals form dropped: %+v code=%d", c, code)
	}
	pub = []string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth"}
	c, code = parseMCPPublish(pub, false)
	if code != 0 || c.resourceFile != "" {
		t.Fatalf("default must be no handoff: %+v code=%d", c, code)
	}
}

// The binding write must be atomic and owner-only: strict discovery
// reads the file concurrently, so a torn write would misverify the
// resource; a world-readable file would leak deployment topology.
func TestWriteResourceBindingAtomic(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/resource.url"
	if err := writeResourceBinding(path, "https://relay.example/r/route1/mcp"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "https://relay.example/r/route1/mcp" {
		t.Fatalf("binding=%q", raw)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("binding mode=%o, want 600", st.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("leftover temp files in binding dir: %v", entries)
	}
	if err := writeResourceBinding(dir+"/no-such-dir/x", "https://x/"); err == nil {
		t.Fatal("write into missing dir succeeded, want failure (caller abandons route)")
	}
}

// Every abort-after-registration path must attempt the route DELETE
// with the route-owning lease ID and surface its outcome independently
// of the lease close (audit P1): a closed lease denies forwarding, but
// the route row must not linger unverified.
func TestAbandonPublishedRouteDeletesAndReports(t *testing.T) {
	var gotPath string
	del := func(path string) (int, string) {
		gotPath = path
		return http.StatusInternalServerError, "  relay exploded  \n"
	}
	status, detail := abandonPublishedRoute(del, "lse-own", "r-1")
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want passthrough", status)
	}
	if detail != "relay exploded" {
		t.Fatalf("detail untrimmed: %q", detail)
	}
	want := "/v1/agent/lease/lse-own/mcp-route/r-1"
	if gotPath != want {
		t.Fatalf("delete path = %q, want %q", gotPath, want)
	}
}

// Remote publication of operator-selected subprocesses is disabled
// (P0-1, P0-2): neither auth mode may combine with --stdio, in publish
// or serve mode, until the stdio bridge can enforce authentication.
func TestParseMCPPublishStdioDisabled(t *testing.T) {
	for _, serve := range []bool{false, true} {
		for _, auth := range []string{"upstream-oauth", "fixture-anonymous"} {
			argv := []string{"--stdio", "--auth=" + auth, "--dir=/tmp/x", "--env=A=B", "--", "/bin/srv", "--flag"}
			if _, code := parseMCPPublish(argv, serve); code == 0 {
				t.Errorf("stdio publish (serve=%v auth=%s) accepted, want rejection", serve, auth)
			}
		}
	}
}

func TestParseMCPPublishRejects(t *testing.T) {
	bad := [][]string{
		{},                                 // no source
		{"--local=http://127.0.0.1:1/mcp"}, // no auth
		{"--auth=upstream-oauth"},          // no source
		{"--local=http://127.0.0.1:1/mcp", "--auth=bogus"},                      // unknown auth
		{"--local=http://127.0.0.1:1/mcp", "--auth=upstream-oauth", "--stdio"},  // both sources
		{"--local=http://127.0.0.1:1/mcp", "--auth=upstream-oauth", "--public"}, // no public flag
		{"--stdio", "--auth=upstream-oauth"},                                    // stdio without command
	}
	for _, argv := range bad {
		if _, code := parseMCPPublish(argv, false); code == 0 {
			t.Errorf("argv %q accepted, want rejection", argv)
		}
	}
	if code := func() int { _, c := parseMCPPublish([]string{"--local=x"}, true); return c }(); code == 0 {
		t.Error("serve without auth accepted")
	}
}

func TestParseMCPLocalURL(t *testing.T) {
	good := map[string]struct {
		port int
		v6   bool
	}{
		"http://127.0.0.1:8765/mcp": {8765, false},
		"http://127.0.0.1:80/mcp/":  {80, false},
		"http://localhost:3000/mcp": {3000, false},
		"http://[::1]:9000/mcp":     {9000, true},
	}
	for raw, want := range good {
		port, v6, err := parseMCPLocalURL(raw)
		if err != nil || port != want.port || v6 != want.v6 {
			t.Errorf("%q: got (%d, %v, %v), want (%d, %v, nil)", raw, port, v6, err, want.port, want.v6)
		}
	}
	bad := []string{
		"http://127.0.0.1:8765/other",      // path must be /mcp
		"http://127.0.0.1:8765/",           // empty path normalizes to /mcp? no: root is not /mcp
		"http://example.com:8765/mcp",      // not loopback
		"http://192.168.1.5:8765/mcp",      // not loopback
		"https://127.0.0.1:8765/mcp",       // http only (loopback probe is http)
		"http://127.0.0.1/mcp",             // no explicit port
		"http://127.0.0.1:0/mcp",           // bad port
		"http://127.0.0.1:99999/mcp",       // bad port
		"not-a-url:%%%/mcp",                // unparseable
		"http://user@127.0.0.1:8765/mcp",   // userinfo has no publishing semantics
		"http://127.0.0.1:8765/mcp?x=1",    // query has no publishing semantics
		"http://127.0.0.1:8765/mcp#frag",   // fragment has no publishing semantics
		"http://user@[::1]:8765/mcp?x=1#f", // combined smuggling shape
	}
	for _, raw := range bad {
		if _, _, err := parseMCPLocalURL(raw); err == nil {
			t.Errorf("%q accepted, want rejection", raw)
		}
	}
}

func TestMCPAccessModeMapping(t *testing.T) {
	if got := mcpAccessMode("upstream-oauth"); got != "mcp_upstream_oauth" {
		t.Errorf("oauth maps to %q", got)
	}
	if got := mcpAccessMode("fixture-anonymous"); got != "mcp_anonymous_fixture" {
		t.Errorf("fixture maps to %q", got)
	}
}

func TestParseMCPPublishExitCodes(t *testing.T) {
	if _, code := parseMCPPublish(nil, false); code != apperr.ExitCLIValidation {
		t.Errorf("empty argv: code=%d, want %d", code, apperr.ExitCLIValidation)
	}
}

// mcpProbeFixture serves scripted JSON-RPC replies keyed by method. A nil
// reply means HTTP 404 for that method.
func mcpProbeFixture(t *testing.T, replies map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		seen = append(seen, in.Method)
		body, ok := replies[in.Method]
		if !ok {
			http.Error(w, "unknown method", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})), &seen
}

func probeTarget(s *httptest.Server) string {
	return strings.TrimPrefix(s.URL, "http://")
}

// A tools/list answer whose id does not echo the modern request must
// NOT verify on the modern path: the probe falls back to the legacy
// handshake, which then fails closed at initialize. The modern attempt
// goes first, so the seen order is tools/list, then initialize.
func TestProbeMCPProtocolRequiresInitialize(t *testing.T) {
	srv, seen := mcpProbeFixture(t, map[string]string{
		"tools/list": `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"ping"}]}}`,
	})
	defer srv.Close()
	status, verified := probeMCPProtocol(probeTarget(srv), "mcp_upstream_oauth")
	if verified {
		t.Fatalf("tools/list-only server verified: %q", status)
	}
	if !strings.HasPrefix(status, "initialize ") {
		t.Fatalf("failure must blame initialize, got %q", status)
	}
	want := []string{"tools/list", "initialize"}
	if len(*seen) != len(want) {
		t.Fatalf("probe count wrong, saw %q", *seen)
	}
	for i := range want {
		if (*seen)[i] != want[i] {
			t.Fatalf("probe order wrong, saw %q", *seen)
		}
	}
}

func TestProbeMCPProtocolFullHandshake(t *testing.T) {
	srv, seen := mcpProbeFixture(t, map[string]string{
		"initialize":                `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"fx"}}}`,
		"notifications/initialized": `{}`,
		"tools/list":                `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"ping"}]}}`,
	})
	defer srv.Close()
	for _, mode := range []string{"mcp_upstream_oauth", "mcp_anonymous_fixture"} {
		status, verified := probeMCPProtocol(probeTarget(srv), mode)
		if !verified {
			t.Fatalf("mode %s: full handshake not verified: %q", mode, status)
		}
		if !strings.HasPrefix(status, "ok (") {
			t.Fatalf("mode %s: status %q, want ok prefix", mode, status)
		}
	}
	// Modern tools/list attempt first (id mismatch on the legacy
	// fixture), then initialize → notification → tools/list per mode.
	want := []string{"tools/list", "initialize", "notifications/initialized", "tools/list",
		"tools/list", "initialize", "notifications/initialized", "tools/list"}
	if len(*seen) != len(want) {
		t.Fatalf("probe count wrong, saw %q", *seen)
	}
	for i := range want {
		if (*seen)[i] != want[i] {
			t.Fatalf("probe order wrong, saw %q", *seen)
		}
	}
}

func TestProbeMCPProtocolRejectsBadReplies(t *testing.T) {
	cases := map[string]map[string]string{
		"missing tools array": {
			"initialize": `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`,
			"tools/list": `{"jsonrpc":"2.0","id":2,"result":{}}`,
		},
		"error envelope": {
			"initialize": `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"nope"}}`,
		},
	}
	for name, replies := range cases {
		srv, _ := mcpProbeFixture(t, replies)
		status, verified := probeMCPProtocol(probeTarget(srv), "mcp_upstream_oauth")
		srv.Close()
		if verified {
			t.Errorf("%s: verified, want rejection: %q", name, status)
		}
	}
}

func TestProbeMCPProtocolUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := ln.Addr().String()
	_ = ln.Close()
	status, verified := probeMCPProtocol(target, "mcp_upstream_oauth")
	if verified {
		t.Fatalf("closed port verified: %q", status)
	}
	if !strings.HasPrefix(status, "initialize unreachable (") {
		t.Fatalf("status %q, want initialize unreachable prefix", status)
	}
}

func TestProbeMCPProtocolNotApplicable(t *testing.T) {
	status, verified := probeMCPProtocol("127.0.0.1:1", "protected")
	if !verified || !strings.HasPrefix(status, "not-applicable") {
		t.Fatalf("non-MCP lease: verified=%v status=%q", verified, status)
	}
}

// A green doctor exit must mean a verified usable connection (or a lease
// the probe does not apply to). Unknown/unreachable/invalid protocol
// health fails the oracle.
func TestDoctorProtocolExit(t *testing.T) {
	if got := doctorProtocolExit("protected", false); got != apperr.ExitOK {
		t.Errorf("non-MCP mode unverified: got %d want OK", got)
	}
	if got := doctorProtocolExit("mcp_upstream_oauth", true); got != apperr.ExitOK {
		t.Errorf("verified MCP: got %d want OK", got)
	}
	if got := doctorProtocolExit("mcp_upstream_oauth", false); got != apperr.ExitProtocol {
		t.Errorf("unverified MCP oauth: got %d want ExitProtocol", got)
	}
	if got := doctorProtocolExit("mcp_anonymous_fixture", false); got != apperr.ExitProtocol {
		t.Errorf("unverified MCP fixture: got %d want ExitProtocol", got)
	}
}

// MCP publication defaults to a bounded lease TTL so a failed remote
// close cannot leave an indefinite exposure window; an explicit --ttl
// (or config default) is respected (P1-8).
func TestMCPPublishBoundedDefaultTTL(t *testing.T) {
	opts, code := mcpTunnelOptions(8765, false, mcpPublishConfig{auth: "upstream-oauth"})
	if code != 0 {
		t.Fatalf("tunnel options rejected: code=%d", code)
	}
	if opts.cfg.TTLSeconds != 12*3600 {
		t.Fatalf("default publish TTL = %d, want 43200", opts.cfg.TTLSeconds)
	}
	opts, code = mcpTunnelOptions(8765, false, mcpPublishConfig{auth: "upstream-oauth", ttl: "2h"})
	if code != 0 {
		t.Fatalf("explicit ttl rejected: code=%d", code)
	}
	if opts.cfg.TTLSeconds != 7200 {
		t.Fatalf("explicit publish TTL = %d, want 7200", opts.cfg.TTLSeconds)
	}
}

// `mcp publish` / `mcp serve` accept an explicit --relay URL (both
// `--relay URL` and `--relay=URL`); it names the relay for the relay
// management API calls AND the tunnel.
func TestParseMCPPublishRelayFlag(t *testing.T) {
	// Both `--relay URL` and `--relay=URL` must parse identically, in
	// publish and serve mode: the flag names the relay for the
	// management API calls and the tunnel.
	for _, tc := range []struct {
		argv  []string
		serve bool
	}{
		{[]string{"--local", "http://127.0.0.1:8765/mcp", "--auth", "upstream-oauth", "--relay", "https://relay.example.com"}, false},
		{[]string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--relay=https://relay.example.com"}, false},
		{[]string{"--local", "http://127.0.0.1:8765/mcp", "--auth", "upstream-oauth", "--relay", "https://relay.example.com"}, true},
		{[]string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--relay=https://relay.example.com"}, true},
	} {
		c, code := parseMCPPublish(tc.argv, tc.serve)
		if code != 0 {
			t.Fatalf("serve=%v argv %q rejected: code=%d", tc.serve, tc.argv, code)
		}
		if c.relay != "https://relay.example.com" {
			t.Fatalf("serve=%v argv %q dropped --relay: %+v", tc.serve, tc.argv, c)
		}
	}
	// Absent --relay stays empty so ordinary precedence applies.
	c, code := parseMCPPublish([]string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth"}, false)
	if code != 0 || c.relay != "" {
		t.Fatalf("absent --relay must resolve to empty: %+v code=%d", c, code)
	}
}

// An invalid --relay is rejected before any key load, probe, tunnel, or
// remote call, with the CLI-validation exit and a usage line that names
// --relay so the operator can see the accepted shape.
func TestParseMCPPublishRelayInvalid(t *testing.T) {
	for _, raw := range []string{
		"ftp://relay.example.com",  // not http(s)
		"https://",                 // missing host
		"not-a-url",                // unparseable / no scheme
		"relay.example.com",        // scheme-less
		"http://192.168.1.10:8080", // remote plaintext (login policy)
	} {
		argv := []string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--relay", raw}
		var code int
		out := captureOutput(t, func() { _, code = parseMCPPublish(argv, false) })
		if code != apperr.ExitCLIValidation {
			t.Errorf("--relay %q: code=%d, want ExitCLIValidation(%d)", raw, code, apperr.ExitCLIValidation)
		}
		if !strings.Contains(out, "--relay") {
			t.Errorf("--relay %q: diagnostic does not mention --relay: %q", raw, out)
		}
	}
	// Missing value fails closed too.
	var code int
	out := captureOutput(t, func() {
		_, code = parseMCPPublish([]string{"--local=http://127.0.0.1:8765/mcp", "--auth=upstream-oauth", "--relay"}, false)
	})
	if code != apperr.ExitCLIValidation || !strings.Contains(out, "--relay") {
		t.Fatalf("missing --relay value: code=%d out=%q", code, out)
	}
}

// `ocliv mcp PORT` rewrites to publish argv; --relay must survive the
// rewrite and still pin upstream-oauth.
func TestMCPPortAliasForwardsRelay(t *testing.T) {
	pub, ok := mcpPortAliasArgs([]string{"3000", "--relay", "https://relay.example.com"})
	if !ok {
		t.Fatal("numeric port alias not recognized")
	}
	c, code := parseMCPPublish(pub, false)
	if code != 0 {
		t.Fatalf("alias argv %q rejected: code=%d", pub, code)
	}
	if c.relay != "https://relay.example.com" || c.localURL != "http://127.0.0.1:3000/mcp" || c.auth != "upstream-oauth" {
		t.Fatalf("alias misparsed: %+v", c)
	}
}

// Relay precedence is exactly: explicit --relay > OCLIV_RELAY_URL >
// agent config file relay_url > built-in default.
func TestResolveMCPRelayPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OCLIV_RELAY_URL", "https://from-env.example.com")
	_, _, cfgPath, err := agentFiles()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("relay_url = https://from-file.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := resolveMCPRelay("https://explicit.example.com"); got != "https://explicit.example.com" {
		t.Fatalf("explicit --relay lost to env/config: %q", got)
	}
	if got := resolveMCPRelay(""); got != "https://from-env.example.com" {
		t.Fatalf("env did not beat config file: %q", got)
	}
	t.Setenv("OCLIV_RELAY_URL", "")
	if got := resolveMCPRelay(""); got != "https://from-file.example.com" {
		t.Fatalf("config file relay_url not used: %q", got)
	}
	if err := os.WriteFile(cfgPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveMCPRelay(""); got != config.DefaultRelayURL {
		t.Fatalf("built-in default not used: %q", got)
	}
}

// The tunnel must target the same relay the management calls use: an
// explicit --relay is forwarded into the ordinary tunnel parser (which
// owns flag > env > file > default), not left to a second resolution.
func TestMCPTunnelOptionsForwardsRelay(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OCLIV_RELAY_URL", "https://from-env.example.com")

	opts, code := mcpTunnelOptions(8765, false, mcpPublishConfig{auth: "upstream-oauth", relay: "https://explicit.example.com"})
	if code != 0 {
		t.Fatalf("tunnel options rejected: code=%d", code)
	}
	if opts.cfg.RelayURL != "https://explicit.example.com" {
		t.Fatalf("explicit --relay not forwarded to the tunnel: %q", opts.cfg.RelayURL)
	}
	// Absent --relay keeps the historical env precedence.
	opts, code = mcpTunnelOptions(8765, false, mcpPublishConfig{auth: "upstream-oauth"})
	if code != 0 || opts.cfg.RelayURL != "https://from-env.example.com" {
		t.Fatalf("absent --relay must keep env precedence: %q code=%d", opts.cfg.RelayURL, code)
	}
}

// A relay that cannot be reached must be NAMED in the generic failure
// diagnostic; specific hints and exit codes stay unchanged.
func TestTunnelFailureHintNamesRelay(t *testing.T) {
	const relay = "https://other-relay.example.com"
	code, hint := tunnelFailureHint(errTest("relay unreachable: dial tcp: connection refused"), relay)
	if code != apperr.ExitRelayTLS {
		t.Fatalf("exit=%d, want ExitRelayTLS(%d)", code, apperr.ExitRelayTLS)
	}
	if !strings.Contains(hint, relay) {
		t.Fatalf("generic tunnel failure does not name the relay: %q", hint)
	}
	if !strings.Contains(hint, "ocliv doctor") {
		t.Fatalf("corrective action lost: %q", hint)
	}
	// A specific hint is never rewritten.
	if _, hint := tunnelFailureHint(errTest("agent key revoked by operator"), relay); strings.Contains(hint, relay) {
		t.Fatalf("specific auth hint was rewritten with a relay: %q", hint)
	}
	// The attach timeout names the relay too.
	if got := relayNotConfirmedHint(relay); !strings.Contains(got, relay) {
		t.Fatalf("attach timeout does not name the relay: %q", got)
	}
	if got := relayNotConfirmedHint(""); got != "relay did not confirm the tunnel; run `ocliv doctor`" {
		t.Fatalf("relay-less timeout message changed: %q", got)
	}
}

// TestSelectDoctorLeaseIDOrder pins the resolution order: explicit
// --lease, then named selection, then latest-lease fallback. The fixed
// defect rejected a valid named lease whenever it was not the latest
// record, because the latest assignment ran before --name was consulted
// and made the FindByName branch unreachable.
func TestSelectDoctorLeaseIDOrder(t *testing.T) {
	dir := t.TempDir()
	store, err := config.OpenLeaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id, host string) {
		t.Helper()
		if err := store.Save(config.LeaseRecord{
			LeaseID: id, Hostname: host, URL: "https://" + host,
			Port: 3000, AccessMode: "protected",
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mk("lse-alpha", "alpha.t.example.test")
	mk("lse-beta", "beta.t.example.test") // latest

	// A valid non-latest name resolves to its own lease, not the latest.
	got, msg, code := selectDoctorLeaseID(dir, "alpha", "")
	if code != 0 || got != "lse-alpha" {
		t.Fatalf("non-latest name: got %q code %d msg %q", got, code, msg)
	}
	// Bogus name fails closed.
	if _, _, code := selectDoctorLeaseID(dir, "bogus", ""); code != apperr.ExitCLIValidation {
		t.Fatalf("bogus name: want ExitCLIValidation got %d", code)
	}
	// Explicit --lease wins when it agrees with --name.
	got, _, code = selectDoctorLeaseID(dir, "beta", "lse-beta")
	if code != 0 || got != "lse-beta" {
		t.Fatalf("agreeing explicit lease: got %q code %d", got, code)
	}
	// Explicit --lease disagreeing with --name fails closed.
	if _, _, code := selectDoctorLeaseID(dir, "alpha", "lse-beta"); code != apperr.ExitCLIValidation {
		t.Fatalf("mismatched lease: want ExitCLIValidation got %d", code)
	}
	// Empty name falls back to the latest record.
	got, _, code = selectDoctorLeaseID(dir, "", "")
	if code != 0 || got != "lse-beta" {
		t.Fatalf("fallback: got %q code %d, want lse-beta", got, code)
	}
	// Explicit --lease alone needs no store lookup.
	got, _, code = selectDoctorLeaseID(dir, "", "lse-alpha")
	if code != 0 || got != "lse-alpha" {
		t.Fatalf("explicit lease: got %q code %d", got, code)
	}
	// Empty store reports no recorded lease.
	empty := t.TempDir()
	if _, _, code := selectDoctorLeaseID(empty, "", ""); code != apperr.ExitCLIValidation {
		t.Fatalf("empty store: want ExitCLIValidation got %d", code)
	}
}

// The same label on two deployments is ambiguous, not latest-wins:
// name-only selection refuses to guess and names both candidates (P1-4).
func TestSelectDoctorLeaseIDAmbiguousName(t *testing.T) {
	dir := t.TempDir()
	store, err := config.OpenLeaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, relay string }{
		{"lse-r1", "https://r1.test"},
		{"lse-r2", "https://r2.test"},
	} {
		if err := store.Save(config.LeaseRecord{
			LeaseID: tc.id, Hostname: "demo.t", URL: "https://demo.t",
			Port: 3000, AccessMode: "protected", RelayURL: tc.relay, KeyID: "key-1",
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, msg, code := selectDoctorLeaseID(dir, "demo", "")
	if code != apperr.ExitCLIValidation {
		t.Fatalf("ambiguous name: want ExitCLIValidation got %d", code)
	}
	if !strings.Contains(msg, "lse-r1") || !strings.Contains(msg, "lse-r2") || !strings.Contains(msg, "--lease") {
		t.Fatalf("ambiguous message hides candidates: %q", msg)
	}
}
