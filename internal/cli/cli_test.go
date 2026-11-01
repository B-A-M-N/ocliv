package cli

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/server"
)

// withHome redirects the agent data dir to a temp dir (unenrolled: no key).
func withHome(t *testing.T, files map[string]string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if len(files) > 0 {
		dir := filepath.Join(home, ".config", "ocliv")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// errTest is a static test error.
type errTest string

func (e errTest) Error() string { return string(e) }

// Valid parses must get PAST argument parsing. Without enrollment the
// command stops at loadKey with ExitAuth; a parse failure returns
// ExitCLIValidation before that point.
func TestTunnelFlagFormsParse(t *testing.T) {
	forms := [][]string{
		{"3000"},
		{"3000", "--public"},
		{"3000", "--ipv6"},
		{"3000", "--ttl", "2h"},
		{"3000", "--ttl=2h"},
		{"3000", "--upstream-host", "app.local:3000"},
		{"3000", "--upstream-host=app.local:3000"},
		{"3000", "--relay", "https://relay.example.com"},
		{"3000", "--relay=https://relay.example.com"},
		{"3000", "--name", "demo", "--json", "--no-share-link"},
	}
	for _, argv := range forms {
		withHome(t, nil)
		if code := cmdTunnel(argv); code != apperr.ExitAuth {
			t.Fatalf("%v: want ExitAuth (parsed, unenrolled) got %d", argv, code)
		}
	}
}

// Invalid parses must fail with ExitCLIValidation before any side effects.
func TestTunnelFlagFormsReject(t *testing.T) {
	forms := [][]string{
		{"3000", "--ttl"},            // space form without a value
		{"3000", "--ttl=bogus"},      // unparseable duration
		{"3000", "--ttl=-1h"},        // non-positive duration
		{"3000", "--bogus"},          // unknown flag
		{"3000", "--upstream-host"},  // space form without a value
		{"notaport"},                 // bad port
		{"3000", "extra", "widgets"}, // unexpected positional
	}
	for _, argv := range forms {
		withHome(t, nil)
		if code := cmdTunnel(argv); code != apperr.ExitCLIValidation {
			t.Fatalf("%v: want ExitCLIValidation got %d", argv, code)
		}
	}
}

// A config file default_access_mode other than "protected" must fail loudly
// rather than silently weaken the default (A04, AS-057).
func TestTunnelConfigAccessModeGuard(t *testing.T) {
	withHome(t, map[string]string{"config.toml": "default_access_mode = \"public\"\n"})
	if code := cmdTunnel([]string{"3000"}); code != apperr.ExitCLIValidation {
		t.Fatalf("public default_access_mode: want ExitCLIValidation got %d", code)
	}
	withHome(t, map[string]string{"config.toml": "default_ttl = \"bogus\"\n"})
	if code := cmdTunnel([]string{"3000"}); code != apperr.ExitCLIValidation {
		t.Fatalf("bad default_ttl: want ExitCLIValidation got %d", code)
	}
	// A well-formed file parses fine (then stops unenrolled).
	withHome(t, map[string]string{"config.toml": "default_access_mode = \"protected\"\ndefault_ttl = \"1h\"\n"})
	if code := cmdTunnel([]string{"3000"}); code != apperr.ExitAuth {
		t.Fatalf("valid config file: want ExitAuth got %d", code)
	}
}

func TestLoginRejectsPlaintextRelay(t *testing.T) {
	// Plaintext enrollment to the network must fail before any network
	// traffic (B02). Loopback http stays allowed for local development.
	writeCode := func(t *testing.T, home string) string {
		t.Helper()
		p := filepath.Join(home, "code.txt")
		if err := os.WriteFile(p, []byte("CODE"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	cf := writeCode(t, home)
	if code := cmdLogin([]string{"--relay", "http://203.0.113.9:8443", "--code-file", cf}); code != apperr.ExitCLIValidation {
		t.Fatalf("remote http relay: want ExitCLIValidation got %d", code)
	}
	// argv codes are gone entirely (A07).
	home2 := t.TempDir()
	t.Setenv("HOME", home2)
	if code := cmdLogin([]string{"--relay", "http://127.0.0.1:9", "--code", "CODE"}); code != apperr.ExitCLIValidation {
		t.Fatalf("--code argv: want ExitCLIValidation (removed) got %d", code)
	}
	// Loopback http still parses (fails later at unreachable relay).
	home3 := t.TempDir()
	t.Setenv("HOME", home3)
	cf3 := writeCode(t, home3)
	if code := cmdLogin([]string{"--relay", "http://127.0.0.1:9", "--code-file", cf3}); code == apperr.ExitCLIValidation {
		t.Fatal("loopback http relay rejected: local development must keep working")
	}
}

// TestLoginMergesConfig: enrollment records the relay URL while preserving
// existing config keys (R6), and reads the code from a file (A07).
func TestLoginMergesConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "ocliv")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("default_ttl = \"1h\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	codePath := filepath.Join(home, "code.txt")
	if err := os.WriteFile(codePath, []byte("  CODE123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enroll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"key_id":"key-abc","tenant_id":"ten-1"}`))
	}))
	defer enroll.Close()
	if code := cmdLogin([]string{"--relay", enroll.URL, "--code-file", codePath}); code != apperr.ExitOK {
		t.Fatalf("login: want ExitOK got %d", code)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "default_ttl") {
		t.Fatalf("login truncated existing config: %q", raw)
	}
	if !strings.Contains(string(raw), enroll.URL) {
		t.Fatalf("login did not record relay_url: %q", raw)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.key")); err != nil {
		t.Fatalf("key not saved: %v", err)
	}
}

// TestLoginRefusesOverwriteBeforeNetwork: a second login over an existing
// enrollment must fail BEFORE contacting the relay, so the one-time
// enrollment code is not burned by a doomed attempt (H07: no silent secret
// overwrite, no implicit loss on retry).
func TestLoginRefusesOverwriteBeforeNetwork(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	codePath := filepath.Join(home, "code.txt")
	if err := os.WriteFile(codePath, []byte("CODE-ONE"), 0o600); err != nil {
		t.Fatal(err)
	}
	hits := 0
	enroll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(`{"key_id":"key-abc","tenant_id":"ten-1"}`))
	}))
	defer enroll.Close()
	if code := cmdLogin([]string{"--relay", enroll.URL, "--code-file", codePath}); code != apperr.ExitOK {
		t.Fatalf("first login: want ExitOK got %d", code)
	}
	keyPath := filepath.Join(home, ".config", "ocliv", "agent.key")
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codePath, []byte("CODE-TWO"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdLogin([]string{"--relay", enroll.URL, "--code-file", codePath}); code == apperr.ExitOK {
		t.Fatal("second login over existing enrollment succeeded: secret overwritten")
	}
	if hits != 1 {
		t.Fatalf("second login contacted relay %d times: code burned on doomed attempt", hits)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("existing agent key modified by refused login")
	}
}

// captureStdout redirects os.Stdout to a pipe while fn runs and returns
// everything written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestIsTerminalStdout(t *testing.T) {
	// A pipe is never a terminal.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	got := isTerminalStdout()
	os.Stdout = old
	w.Close()
	r.Close()
	if got {
		t.Fatal("pipe reported as terminal")
	}
}

// Five rapid re-attachments with no consumer must never block the
// runner's networking-path callback, and the consumer must observe the
// latest lease/URL once it catches up (P1-01).
func TestAttachEventsNeverBlockReconnects(t *testing.T) {
	events := newAttachEvents()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i <= 5; i++ {
			events.onAttach(agent.Attached{
				LeaseID:    "lease-1",
				Generation: uint64(i),
				URL:        "https://t.example.test/",
			})
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("attach callback blocked: reconnect would stall the runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, ok := events.next(ctx)
	if !ok {
		t.Fatal("no attachment observed")
	}
	if got.Generation != 5 || got.LeaseID != "lease-1" {
		t.Fatalf("latest attachment lost: %+v", got)
	}
}

// A terminal runner error must map to a stable exit code with a
// corrective action, never a silent hang or a generic success (P1-02).
// The health listener must surface bind failures instead of silently
// dropping them, and shut down cleanly on request.
func TestStartHealthListenerBindAndShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := (&server.Health{Ready: func() bool { return true }}).Handler()
	if _, err := startHealthListener(ln.Addr().String(), h); err == nil {
		t.Fatal("health listener bound over an occupied port without error")
	}
	srv, err := startHealthListener("127.0.0.1:0", h)
	if err != nil {
		t.Fatalf("health listener on a free port: %v", err)
	}
	addr := srv.Addr
	if ln2, err := net.Listen("tcp", addr); err == nil {
		ln2.Close()
		t.Fatal("health listener did not bind its port")
	}
	resp, err := http.Get("http://" + addr + "/health/live")
	if err != nil {
		t.Fatalf("health endpoint: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("health shutdown: %v", err)
	}
}

// The health listener is operator-configurable but loopback-only (P2):
// non-loopback --health-listen values fail validation like --listen.
func TestHealthListenEnforcesLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:18080", "[::1]:18081", "localhost:18082"} {
		raw, seen := healthListenFlag([]string{"--health-listen=" + ok})
		if !seen || raw != ok {
			t.Fatalf("health flag %q not parsed", ok)
		}
		if _, err := parseRelayListen(raw, "health-listen"); err != nil {
			t.Fatalf("loopback health %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:18080", ":18080", "192.168.1.5:18080"} {
		if _, err := parseRelayListen(bad, "health-listen"); err == nil {
			t.Fatalf("non-loopback health %q accepted", bad)
		}
	}
}

// The relay ingress must stay behind the TLS edge: only loopback
// listeners are accepted (P0-07).
func TestRelayListenEnforcesLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:8080", "127.0.0.2:8080", "[::1]:8080", "localhost:8080"} {
		if _, err := parseRelayListen(ok, "listen"); err != nil {
			t.Fatalf("loopback %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:8080", ":8080", "192.168.1.5:8080", "example.com:8080", "[::]:8080", "8080"} {
		if _, err := parseRelayListen(bad, "listen"); err == nil {
			t.Fatalf("non-loopback %q accepted", bad)
		}
	}
}

// Both `--listen HOST:PORT` and `--listen=HOST:PORT` parse identically:
// a space-form public listener must also refuse before binding anything
// (silent flag-drop on a security-relevant flag is not acceptable).
func TestRelayServeSpaceFormListenRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	code := cmdRelayServe([]string{"--listen", "0.0.0.0:18081", "--data", dir, "--domain=ocliv.test"})
	if code != apperr.ExitCLIValidation {
		t.Fatalf("space-form public listen: exit %d, want %d", code, apperr.ExitCLIValidation)
	}
	if _, err := os.Stat(filepath.Join(dir, "ocliv.db")); !os.IsNotExist(err) {
		t.Fatalf("space-form public listen created relay state before refusal")
	}
}

// The production entry point must refuse a public listener before
// binding anything: no socket, no database, no readiness (P0-07).
func TestRelayServeRefusesPublicListen(t *testing.T) {
	// Wildcard, LAN, and tailnet-style listeners would bypass the TLS
	// edge: all must fail before binding or creating relay state (P0-02).
	// A valid domain is supplied so the refusal is proven to come from
	// listen validation, not domain validation.
	for _, listen := range []string{"0.0.0.0:18081", "10.9.66.20:18081", "100.64.0.1:18081", "192.168.1.10:18081"} {
		dir := filepath.Join(t.TempDir(), "data")
		code := cmdRelayServe([]string{"--listen=" + listen, "--data", dir, "--domain=ocliv.test"})
		if code != apperr.ExitCLIValidation {
			t.Fatalf("listen %s exit = %d, want %d", listen, code, apperr.ExitCLIValidation)
		}
		if _, err := os.Stat(filepath.Join(dir, "ocliv.db")); !os.IsNotExist(err) {
			t.Fatalf("listen %s created relay state before refusal", listen)
		}
	}
}

// The production domain has no safe default: empty, placeholder, and
// malformed values must refuse startup instead of serving the wrong
// namespace (A05, A06, D01, H02).
func TestParseRelayDomain(t *testing.T) {
	for _, ok := range []string{"tunnels.example.net", "a-b.c12.dev", "relay.mydomain.io"} {
		if _, err := parseRelayDomain(ok); err != nil {
			t.Fatalf("domain %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "  ", "example.com", "example.net", "example.org",
		"localhost", "single", ".lead.dot", "trail.dot.", "bad_char!.com", "-lead.com", "toolonglabel" + strings.Repeat("x", 60) + ".com"} {
		if _, err := parseRelayDomain(bad); err == nil {
			t.Fatalf("domain %q accepted", bad)
		}
	}
}

// --mcp-host must name one exact public hostname: no scheme, port,
// path, placeholder, or bare label may enable path-route ingress.
func TestParseMCPHost(t *testing.T) {
	for _, ok := range []string{"relay.example.org", "Relay.Example.ORG", "a-b.c12.dev"} {
		got, err := parseMCPHost(ok)
		if err != nil {
			t.Fatalf("mcp host %q rejected: %v", ok, err)
		}
		if got != strings.ToLower(ok) {
			t.Fatalf("mcp host %q = %q, want lowercased", ok, got)
		}
	}
	for _, bad := range []string{"", "  ", "example.com", "single", "localhost",
		"bad_char!.com", "-lead.com", "https://relay.example.org",
		"relay.example.org:8080", "relay.example.org/mcp"} {
		if _, err := parseMCPHost(bad); err == nil {
			t.Fatalf("mcp host %q accepted", bad)
		}
	}
}

// An invalid --relay-host must refuse before binding anything or
// creating relay state, exactly like other relay validation failures.
// A bare or placeholder hostname never becomes the control authority.
func TestRelayServeRefusesBadRelayHost(t *testing.T) {
	for _, argv := range [][]string{
		{"--listen=127.0.0.1:18081", "--domain=ocliv.test", "--relay-host=example.com"},
		{"--listen=127.0.0.1:18081", "--domain=ocliv.test", "--relay-host", "single"},
		{"--listen=127.0.0.1:18081", "--domain=ocliv.test", "--relay-host="},
	} {
		dir := filepath.Join(t.TempDir(), "data")
		if code := cmdRelayServe(append(argv, "--data", dir)); code != apperr.ExitCLIValidation {
			t.Fatalf("argv %v: exit %d, want %d", argv, code, apperr.ExitCLIValidation)
		}
		if _, err := os.Stat(filepath.Join(dir, "ocliv.db")); !os.IsNotExist(err) {
			t.Fatalf("argv %v created relay state before refusal", argv)
		}
	}
}

// An invalid --mcp-host must refuse before binding anything or creating
// relay state, exactly like other relay validation failures.
func TestRelayServeRefusesBadMCPHost(t *testing.T) {
	for _, argv := range [][]string{
		{"--listen=127.0.0.1:18081", "--domain=ocliv.test", "--mcp-host=example.com"},
		{"--listen=127.0.0.1:18081", "--domain=ocliv.test", "--mcp-host", "single"},
		{"--listen=127.0.0.1:18081", "--domain=ocliv.test", "--mcp-host="},
	} {
		dir := filepath.Join(t.TempDir(), "data")
		if code := cmdRelayServe(append(argv, "--data", dir)); code != apperr.ExitCLIValidation {
			t.Fatalf("argv %v: exit %d, want %d", argv, code, apperr.ExitCLIValidation)
		}
		if _, err := os.Stat(filepath.Join(dir, "ocliv.db")); !os.IsNotExist(err) {
			t.Fatalf("argv %v created relay state before refusal", argv)
		}
	}
}

// The installed entry point must refuse a missing or placeholder domain
// before binding anything.
func TestRelayServeRefusesPlaceholderDomain(t *testing.T) {
	for _, argv := range [][]string{
		{"--listen=127.0.0.1:18081"},
		{"--listen=127.0.0.1:18081", "--domain=example.com"},
		{"--listen=127.0.0.1:18081", "--domain="},
	} {
		if code := cmdRelayServe(append(argv, "--data", t.TempDir())); code != apperr.ExitCLIValidation {
			t.Fatalf("argv %v: exit %d, want %d", argv, code, apperr.ExitCLIValidation)
		}
	}
}

// relay init is preparation-only: it must say so instead of implying
// it provisions the deployment.
func TestRelayInitLabelsPreparationOnly(t *testing.T) {
	out := captureStdout(t, func() {
		if code := cmdRelayInit([]string{"--domain", "example.com", "--data", t.TempDir()}); code != apperr.ExitOK {
			t.Fatalf("exit %d", code)
		}
	})
	if !strings.Contains(out, "preparation-only") {
		t.Fatalf("relay init does not label itself preparation-only:\n%s", out)
	}
}

// Machine-readable output is always secret-free (A07): the share link
// is a Bearer [REDACTED] and never appears in JSON, with or without
// opt-in flags. Delivery happens only via verified TTY or
// --share-link-file PATH.
func TestAttachJSONMapNeverCarriesSecret(t *testing.T) {
	a := agent.Attached{LeaseID: "l1", URL: "https://h/", Hostname: "h", ShareURL: "https://h/s#t=secret"}
	if got := attachJSONMap(a); got["share_url"] != "" {
		t.Fatalf("JSON leaks share_url: %v", got)
	}
	if got := attachJSONMap(agent.Attached{LeaseID: "l1"}); got["lease_id"] != "l1" {
		t.Fatalf("attach record broken: %v", got)
	}
}

// The share capability reaches only an explicitly requested file, with
// owner-only permissions; nothing is written without a path.
func TestWriteShareLinkFile(t *testing.T) {
	dir := t.TempDir()
	a := agent.Attached{LeaseID: "l1", ShareURL: "https://h/s#t=secret"}
	if err := writeShareLinkFile("", a); err != nil {
		t.Fatalf("empty path must be a no-op: %v", err)
	}
	if err := writeShareLinkFile(filepath.Join(dir, "s"), agent.Attached{LeaseID: "l1"}); err != nil {
		t.Fatalf("empty share URL must be a no-op: %v", err)
	}
	dst := filepath.Join(dir, "sub", "share.txt")
	if err := writeShareLinkFile(dst, a); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil || strings.TrimSpace(string(raw)) != "https://h/s#t=secret" {
		t.Fatalf("share file content = %q, err = %v", raw, err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("share file perms = %v, err = %v", fi.Mode(), err)
	}
}

// A failed lease close must be reported with the lease ID so the
// operator knows access may linger until TTL expiry (P1-product).
func TestCloseWarningReportsFailures(t *testing.T) {
	if got := closeWarning("lease-1", 200, nil); got != "" {
		t.Fatalf("success reported a warning: %q", got)
	}
	for _, tc := range []struct {
		name   string
		status int
		body   []byte
	}{
		{"transport failure", 0, nil},
		{"server error", 500, []byte("boom")},
	} {
		got := closeWarning("lease-1", tc.status, tc.body)
		if got == "" {
			t.Fatalf("%s: no warning", tc.name)
		}
		if !strings.Contains(got, "lease-1") {
			t.Fatalf("%s: warning omits lease id: %q", tc.name, got)
		}
	}
}

// Tunnel options share login's single relay-URL policy (CheckRelayTLS):
// https everywhere, http only for loopback local development. Remote
// plaintext fails here, never at dial time.
func TestParseTunnelOptionsRelayTLS(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, code := parseTunnelOptions([]string{"3000", "--relay", "http://127.0.0.1:18081"}); code != 0 {
		t.Fatalf("loopback http relay: code=%d, want 0", code)
	}
	if _, code := parseTunnelOptions([]string{"3000", "--relay", "https://relay.example.org"}); code != 0 {
		t.Fatalf("https relay: code=%d, want 0", code)
	}
	if _, code := parseTunnelOptions([]string{"3000", "--relay", "http://192.168.1.10:8080"}); code == 0 {
		t.Fatalf("remote plaintext relay accepted")
	}
}

func TestRunnerExitMapsTerminalFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
	}{
		{"nil is clean", nil, apperr.ExitCleanShutdown},
		{"enrollment", errTest("enrollment rejected: bad code"), apperr.ExitAuth},
		{"revoked", errTest("agent key revoked by operator"), apperr.ExitAuth},
		{"protocol", errTest("protocol_incompatible: relay too old"), apperr.ExitProtocol},
		{"plaintext", errTest("must use https for non-loopback relay"), apperr.ExitRelayTLS},
		{"denied", errTest("agent lease permanently denied by relay"), apperr.ExitAuth},
		{"other", errTest("websocket dial: connection refused"), apperr.ExitRelayTLS},
	}
	for _, tc := range cases {
		code, hint := runnerExit(tc.err)
		if code != tc.code {
			t.Errorf("%s: exit %d, want %d (hint %q)", tc.name, code, tc.code, hint)
		}
		if tc.err != nil && hint == "" {
			t.Errorf("%s: empty corrective hint", tc.name)
		}
	}
}

// cmdStatus must report the authoritative relay state when reachable
// and label everything else UNKNOWN instead of echoing a stale cache.
func TestRenderStatusDistinguishesAuthoritative(t *testing.T) {
	local := map[string]any{"lease_id": "l1", "url": "https://h/", "access_mode": "private", "port": float64(3000)}
	if out, code := renderStatus(nil, nil, nil, false); code != apperr.ExitOK || !strings.Contains(out, "no active tunnel") {
		t.Fatalf("no lease: code=%d out=%q", code, out)
	}
	remote := map[string]any{"lease_id": "l1", "status": "ACTIVE", "url": "https://h/", "access_mode": "private", "port": float64(3000)}
	if out, _ := renderStatus(local, remote, nil, false); !strings.Contains(out, "ACTIVE") {
		t.Fatalf("authoritative ACTIVE not shown: %q", out)
	}
	revoked := map[string]any{"lease_id": "l1", "status": "REVOKED"}
	if out, _ := renderStatus(local, revoked, nil, false); !strings.Contains(out, "REVOKED") {
		t.Fatalf("authoritative REVOKED not shown: %q", out)
	}
	if out, _ := renderStatus(local, nil, errTest("dial refused"), false); !strings.Contains(out, "UNKNOWN") {
		t.Fatalf("unreachable relay not UNKNOWN: %q", out)
	}
	jout, _ := renderStatus(local, remote, nil, true)
	if !strings.Contains(jout, `"status"`) || !strings.Contains(jout, "ACTIVE") {
		t.Fatalf("json omits authoritative status: %q", jout)
	}
}

// Attached is not the same as routable: status must distinguish a relay
// record with a live route from one whose session is gone, and must never
// claim external reachability (only attachment + relay routing are shown).
func TestRenderStatusDistinguishesRoute(t *testing.T) {
	local := map[string]any{"lease_id": "l1", "url": "https://h/", "access_mode": "private", "port": float64(3000)}
	live := map[string]any{"lease_id": "l1", "status": "ACTIVE", "route_live": true, "live_generation": float64(3)}
	if out, _ := renderStatus(local, live, nil, false); !strings.Contains(out, "live") {
		t.Fatalf("live route not shown: %q", out)
	}
	down := map[string]any{"lease_id": "l1", "status": "ACTIVE", "route_live": false}
	if out, _ := renderStatus(local, down, nil, false); !strings.Contains(out, "no live session") {
		t.Fatalf("dead route not distinguished from attach: %q", out)
	}
	// No route_live key (old relay): route is unknown, never assumed live.
	bare := map[string]any{"lease_id": "l1", "status": "ACTIVE"}
	if out, _ := renderStatus(local, bare, nil, false); !strings.Contains(out, "unknown") {
		t.Fatalf("missing route signal assumed live: %q", out)
	}
	jout, _ := renderStatus(local, down, nil, true)
	if !strings.Contains(jout, `"route"`) || !strings.Contains(jout, "down") {
		t.Fatalf("json omits route state: %q", jout)
	}
}

func TestParseTTLDuration(t *testing.T) {
	if secs, err := parseTTLDuration("2h"); err != nil || secs != 7200 {
		t.Fatalf("2h -> %d, %v", secs, err)
	}
	for _, bad := range []string{"", "bogus", "0s", "-1h", "500ms"} {
		if _, err := parseTTLDuration(bad); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
}

// Files created by the relay process must be owner-only even under a
// permissive umask (P1-3 deployment test): restrictFileCreation sets
// 0077 so SQLite sidecars created mid-run are never group-readable.
// Umask is process-global; saved and restored around the assertion.
func TestRestrictFileCreationMasksSidecars(t *testing.T) {
	prev := syscall.Umask(0o022)
	defer syscall.Umask(prev)
	restrictFileCreation()
	p := filepath.Join(t.TempDir(), "probe")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("file perm = %v err = %v, want owner-only", fi.Mode(), err)
	}
}

// Shutdown uses the live attachment lease ID exactly; there is no
// store fallback (P1-1). A missing attachment identity leaves remote
// state unconfirmed rather than guessing another tunnel's lease.
func TestShutdownUsesLiveAttachmentIDOnly(t *testing.T) {
	dir := t.TempDir()
	fileLease := map[string]any{"lease_id": "lse-file", "port": 3000}
	raw, _ := json.Marshal(fileLease)
	if err := os.WriteFile(filepath.Join(dir, config.LeaseFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := lastLeaseID(dir); got == "" {
		t.Fatal("informational latest-lease lookup broke")
	}
}

// TestAttachEventsSlowAttachObserved pins the P1-01 multiplex contract:
// when a slow first attachment lands after poll has already run empty,
// a multiplex select may consume the wakeup before poll runs again, and
// the attachment must still be delivered. Pre-fix, wait() consumed the
// single signal token, so the follow-up poll found nothing and runTunnel
// hung until its 45s timeout ("relay did not confirm the tunnel").
func TestAttachEventsSlowAttachObserved(t *testing.T) {
	events := newAttachEvents()
	if _, ok := events.poll(); ok {
		t.Fatal("poll on empty sink returned an event")
	}
	events.onAttach(agent.Attached{LeaseID: "lease-1", Generation: 1, URL: "https://t.example.test/"})
	// Lose the race exactly like runTunnel's select: consume the wakeup
	// without delivering.
	select {
	case <-events.wait():
	case <-time.After(10 * time.Second):
		t.Fatal("wakeup never signaled")
	}
	a, ok := events.poll()
	if !ok {
		t.Fatal("slow attachment lost after consumed wakeup")
	}
	if a.LeaseID != "lease-1" || a.Generation != 1 {
		t.Fatalf("wrong attachment delivered: %+v", a)
	}
	// Delivered exactly once: a second poll finds nothing new.
	if _, ok := events.poll(); ok {
		t.Fatal("attachment delivered twice")
	}
	// A newer generation still supersedes.
	events.onAttach(agent.Attached{LeaseID: "lease-1", Generation: 2, URL: "https://t.example.test/"})
	a, ok = events.next(context.Background())
	if !ok || a.Generation != 2 {
		t.Fatalf("superseding attachment not delivered: %+v %v", a, ok)
	}
}
