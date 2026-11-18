package cli

// Slice 1 acceptance: `setup --check` against injected echo endpoints
// reports the observed egress and a path verdict without touching DNS,
// routers, services, or credentials.

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ocliv/internal/apperr"
	"ocliv/internal/relay"
	"ocliv/internal/setup"
	"ocliv/internal/store"
)

func TestSetupCheckReportsEchoVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer srv.Close()
	out := captureStdout(t, func() {
		if code := cmdSetup([]string{"--check", "--echo-v4", srv.URL, "--echo-v6", ""}); code != apperr.ExitOK {
			t.Fatalf("exit=%d", code)
		}
	})
	for _, want := range []string{"203.0.113.9", "nat-ipv4-needs-forward", "UNKNOWN"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup --check missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "direct-ipv4") {
		t.Fatalf("setup --check overclaims direct reachability:\n%s", out)
	}
}

func TestSetupDryRunSendsNothing(t *testing.T) {
	hit := false
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "TESTTOKEN")
	var code int
	out := captureStdout(t, func() {
		code = cmdSetup([]string{"--auto", "--edge", "tunnel", "--hostname", "lab.dynv6.net", "--dry-run", "--echo-v4", echo.URL, "--echo-v6", ""})
	})
	if code != apperr.ExitOK {
		t.Fatalf("exit=%d", code)
	}
	if hit {
		t.Fatal("dry-run sent a live update request")
	}
	if strings.Contains(out, "TESTTOKEN") {
		t.Fatalf("token printed in dry-run output:\n%s", out)
	}
	for _, want := range []string{"203.0.113.9", "dry-run"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry-run missing %q in:\n%s", want, out)
		}
	}
}

func TestSetupLiveUpdateAgainstFixture(t *testing.T) {
	var gotToken, gotHost string
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotHost, gotToken = q.Get("hostname"), q.Get("token")
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "TESTTOKEN")
	var code int
	_ = captureStdout(t, func() {
		code = cmdSetup([]string{"--auto", "--edge", "tunnel", "--hostname", "lab.dynv6.net", "--echo-v4", echo.URL, "--echo-v6", ""})
	})
	if code != apperr.ExitOK {
		t.Fatalf("exit=%d", code)
	}
	if gotHost != "lab.dynv6.net" || gotToken != "TESTTOKEN" {
		t.Fatalf("fixture saw host=%q token=%q", gotHost, gotToken)
	}
}

func TestSetupMissingTokenNeedsAuth(t *testing.T) {
	t.Setenv("DYNV6_TOKEN", "")
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	if code := cmdSetup([]string{"--auto", "--hostname", "lab.dynv6.net", "--echo-v4", echo.URL, "--echo-v6", ""}); code != apperr.ExitAuth {
		t.Fatalf("exit=%d, want %d", code, apperr.ExitAuth)
	}
}

func TestSetupFreshInstallDoesNotPersistBeforeProvisioning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldLookup := setupLookupHost
	setupLookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	}
	defer func() { setupLookupHost = oldLookup }()
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "TESTTOKEN")
	out := t.TempDir()
	var code int
	captured := captureOutput(t, func() {
		code = cmdSetup([]string{"--auto", "--edge", "tunnel", "--hostname", "lab.dynv6.net",
			"--acme-email", "ops@mailtest.invalid-test", "--out", out,
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	// DNS (apex + wildcard) verifies in this fixture, but edge
	// provisioning cannot complete without root/Caddy: the outcome
	// must be ACTION_REQUIRED and the fresh install must NOT record
	// an operational relay_url for an endpoint that was never
	// provisioned. Rendered artifacts stay for manual inspection.
	if code != apperr.ExitRelayTLS {
		t.Fatalf("exit=%d, want %d (provisioning incomplete)", code, apperr.ExitRelayTLS)
	}
	if !strings.Contains(captured, "ACTION REQUIRED") {
		t.Fatalf("incomplete provisioning not labeled ACTION REQUIRED in:\n%s", captured)
	}
	if _, err := os.Stat(filepath.Join(out, "Caddyfile")); err != nil {
		t.Fatalf("deployment not rendered: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".config", "ocliv", "config.toml"))
	if err == nil && strings.Contains(string(raw), "lab.dynv6.net") {
		t.Fatalf("fresh relay_url persisted before provisioning completed:\n%s", raw)
	}
}

func TestShouldPersistRelayURL(t *testing.T) {
	for _, tc := range []struct {
		name        string
		existing    string
		next        string
		provisioned bool
		want        bool
	}{
		{"fresh waits for provisioning", "", "https://lab.dynv6.net", false, false},
		{"fresh persists after provisioning", "", "https://lab.dynv6.net", true, true},
		{"same value waits for provisioning", "https://lab.dynv6.net", "https://lab.dynv6.net", false, false},
		{"same value idempotent after provisioning", "https://lab.dynv6.net", "https://lab.dynv6.net", true, true},
		{"replacement waits for provisioning", "https://old.example", "https://lab.dynv6.net", false, false},
		{"replacement after provisioning", "https://old.example", "https://lab.dynv6.net", true, true},
		{"empty next never persists", "https://old.example", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldPersistRelayURL(tc.existing, tc.next, tc.provisioned); got != tc.want {
				t.Fatalf("shouldPersistRelayURL(%q,%q,%v)=%v, want %v",
					tc.existing, tc.next, tc.provisioned, got, tc.want)
			}
		})
	}
}

func TestSetupWildcardDNSBlocksWithoutRecord(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldLookup := setupLookupHost
	setupLookupHost = func(ctx context.Context, host string) ([]string, error) {
		// Apex resolves; the tunnel wildcard does not exist.
		if strings.Contains(host, ".t.") {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []string{"203.0.113.9"}, nil
	}
	defer func() { setupLookupHost = oldLookup }()
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "TESTTOKEN")
	out := t.TempDir()
	var code int
	captured := captureOutput(t, func() {
		code = cmdSetup([]string{"--auto", "--edge", "tunnel", "--hostname", "lab.dynv6.net",
			"--acme-email", "ops@mailtest.invalid-test", "--out", out,
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	if code != apperr.ExitRelayTLS {
		t.Fatalf("exit=%d, want %d (wildcard unverified)", code, apperr.ExitRelayTLS)
	}
	if !strings.Contains(captured, "*.t.lab.dynv6.net") {
		t.Fatalf("missing exact wildcard record instruction in:\n%s", captured)
	}
	if !strings.Contains(captured, "ACTION REQUIRED") {
		t.Fatalf("blocked setup not labeled ACTION REQUIRED in:\n%s", captured)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".config", "ocliv", "config.toml"))
	if err == nil && strings.Contains(string(raw), "relay_url") {
		t.Fatalf("relay_url persisted before wildcard verified:\n%s", raw)
	}
}

func TestSetupKeepsWorkingRelayURLWhenBlocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("blocked-bootstrap test must not run as root (would execute live provisioning)")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgDir := filepath.Join(home, ".config", "ocliv")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("relay_url = \"https://old.example\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldLookup := setupLookupHost
	setupLookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	}
	defer func() { setupLookupHost = oldLookup }()
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "TESTTOKEN")
	out := t.TempDir()
	var code int
	_ = captureStdout(t, func() {
		code = cmdSetup([]string{"--auto", "--edge", "tunnel", "--hostname", "lab.dynv6.net",
			"--acme-email", "ops@mailtest.invalid-test", "--out", out,
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	// Bootstrap cannot complete here (no root and/or no Caddy), so the
	// outcome must be ACTION_REQUIRED and the working config untouched.
	if code != apperr.ExitRelayTLS {
		t.Fatalf("exit=%d, want %d (provisioning incomplete)", code, apperr.ExitRelayTLS)
	}
	raw, err := os.ReadFile(filepath.Join(cfgDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "https://old.example") {
		t.Fatalf("working relay_url replaced on incomplete provisioning:\n%s", raw)
	}
}

func TestSetupRenderRefusesOnDNSMismatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldLookup := setupLookupHost
	setupLookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"198.51.100.7"}, nil
	}
	defer func() { setupLookupHost = oldLookup }()
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "TESTTOKEN")
	out := t.TempDir()
	var code int
	_ = captureStdout(t, func() {
		code = cmdSetup([]string{"--auto", "--edge", "tunnel", "--hostname", "lab.dynv6.net",
			"--acme-email", "ops@mailtest.invalid-test", "--out", out,
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	if code != apperr.ExitRelayTLS {
		t.Fatalf("exit=%d, want %d (DNS does not match egress)", code, apperr.ExitRelayTLS)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".config", "ocliv", "config.toml"))
	if err == nil && strings.Contains(string(raw), "relay_url") {
		t.Fatalf("unverified relay_url persisted:\n%s", raw)
	}
}

// enrollFixture starts a live relay against a temp store and returns
// the data dir and its loopback URL (plain http is loopback-only, so
// enrollment may proceed per B01/B02).
func enrollFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv, err := relay.New(relay.Options{
		DB: db, Namespace: "t.example.test", RelayHost: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	return dir, "http://" + ln.Addr().String()
}

func TestSetupAutoEnrollEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir, url := enrollFixture(t)
	keyID, code := autoEnroll(url, dir, "home")
	if code != apperr.ExitOK {
		t.Fatalf("auto-enroll exit=%d", code)
	}
	if keyID == "" {
		t.Fatal("auto-enroll returned no key id")
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "ocliv", "agent.key")); err != nil {
		t.Fatalf("agent key not saved: %v", err)
	}
	// Second run must not burn a new code over the existing key (H07).
	if _, code := autoEnroll(url, dir, "home"); code != apperr.ExitOK {
		t.Fatalf("re-run exit=%d, want clean already-enrolled no-op", code)
	}
}

func TestSetupProviderFlowIsReadOnlyWithoutConfirm(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("100.64.5.6\n"))
	}))
	defer echo.Close()
	var code int
	out := captureStdout(t, func() {
		code = cmdSetup([]string{"--auto", "--provider", "oracle",
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	if code != apperr.ExitOK {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "cgnat-no-direct-ipv4") {
		t.Fatalf("provider flow missing CGNAT verdict:\n%s", out)
	}
	if !strings.Contains(out, "Always Free") && !strings.Contains(out, "BLOCKED") {
		t.Fatalf("provider flow shows neither plan nor blocker:\n%s", out)
	}
}

func TestSetupRejectsUnknownProvider(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("100.64.5.6\n"))
	}))
	defer echo.Close()
	if code := cmdSetup([]string{"--auto", "--provider", "bedrock",
		"--echo-v4", echo.URL, "--echo-v6", ""}); code != apperr.ExitCLIValidation {
		t.Fatalf("exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}

func TestSetupRejectsUnknownFlag(t *testing.T) {
	if code := cmdSetup([]string{"--bogus"}); code != apperr.ExitCLIValidation {
		t.Fatalf("exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}

// Slice 5 acceptance: --refresh-dns runs one refresh cycle without
// touching Caddy/systemd/enrollment. Stubs echo + DNS + update.
func TestSetupRefreshDNSChanged(t *testing.T) {
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.9"))
	}))
	defer v4.Close()
	updateHits := 0
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		updateHits++
		w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "refresh-token")
	oldLookup := setup.LookupHost
	setup.LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"198.51.100.9"}, nil
	}
	defer func() { setup.LookupHost = oldLookup }()
	code := 0
	out := captureOutput(t, func() {
		code = cmdSetup([]string{"--refresh-dns", "--hostname", "h.dynv6.net", "--echo-v4", v4.URL})
	})
	if code != apperr.ExitOK {
		t.Fatalf("exit=%d, want %d (out=%q)", code, apperr.ExitOK, out)
	}
	if updateHits != 1 {
		t.Fatalf("update hits=%d, want 1", updateHits)
	}
	if !strings.Contains(out, "address changed") {
		t.Fatalf("output missing change notice: %q", out)
	}
}

func TestSetupRefreshDNSNoChange(t *testing.T) {
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.9"))
	}))
	defer v4.Close()
	updateHits := 0
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		updateHits++
		w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "refresh-token")
	oldLookup := setup.LookupHost
	setup.LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	}
	defer func() { setup.LookupHost = oldLookup }()
	code := 0
	out := captureOutput(t, func() {
		code = cmdSetup([]string{"--refresh-dns", "--hostname", "h.dynv6.net", "--echo-v4", v4.URL})
	})
	if code != apperr.ExitOK {
		t.Fatalf("exit=%d, want %d (out=%q)", code, apperr.ExitOK, out)
	}
	if updateHits != 0 {
		t.Fatalf("update hits=%d, want 0", updateHits)
	}
	if !strings.Contains(out, "already current") {
		t.Fatalf("output missing no-change notice: %q", out)
	}
}

func TestSetupRefreshDNSNeedsHostname(t *testing.T) {
	if code := cmdSetup([]string{"--refresh-dns"}); code != apperr.ExitCLIValidation {
		t.Fatalf("exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}

// The port guidance must not state TCP 80 as unconditional. Adapting
// packaging/caddy/Caddyfile.single-host with a real caddy adapt proves
// that edge binds :443 alone and issues via TLS-ALPN-01, so only the
// default tunnel edge (which can fall back to HTTP-01) needs port 80.
// An operator told to open a port they do not need is actionable
// guidance being wrong, and one told nothing about the exception is
// incomplete, so both halves are pinned.
func TestSetupPortGuidanceDistinguishesEdges(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	var code int
	out := captureStdout(t, func() {
		code = cmdSetup([]string{"--auto", "--echo-v4", echo.URL, "--echo-v6", ""})
	})
	if code != apperr.ExitOK {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "443") {
		t.Fatalf("guidance never names TCP 443, the port every edge needs:\n%s", out)
	}
	// The exact over-claim that must not come back.
	for _, stale := range []string{"TCP 80 and 443", "TCP 80/443"} {
		if strings.Contains(out, stale) {
			t.Fatalf("port guidance still states %q as unconditional:\n%s", stale, out)
		}
	}
	// The exception must be named and attributed to the edge that needs it.
	if !strings.Contains(out, "tunnel edge") {
		t.Fatalf("guidance does not name the edge that still needs port 80:\n%s", out)
	}
	// And it must say why for the single-host edge, or the operator cannot
	// decide which edge to run.
	if !strings.Contains(out, "single-host") {
		t.Fatalf("guidance does not distinguish the single-host edge:\n%s", out)
	}
}

// `--edge` selects the ingress shape for the automated self-hosting path
// (commit f0bc949). A flag that is absent from `ocliv help` is a flag
// operators cannot discover, and the mandate asks for easy configuration.
// This pins it so the flag cannot silently vanish from the help again.
func TestHelpDocumentsSetupEdge(t *testing.T) {
	var code int
	out := captureStdout(t, func() {
		code = Run([]string{"help"})
	})
	if code != 0 {
		t.Fatalf("help exit=%d, want 0", code)
	}
	if !strings.Contains(out, "--edge") {
		t.Fatalf("help does not document the setup --edge flag:\n%s", out)
	}
	// The three accepted values must be named, or the operator cannot
	// choose, and single-host is the one MCP hosting actually needs.
	for _, want := range []string{"single-host", "tunnel", "wildcard"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help does not name --edge value %q:\n%s", want, out)
		}
	}
}

// The single-host edge serves exactly ONE apex hostname and needs no
// wildcard record. `setup --auto` hardcoded --edge tunnel, which both
// rendered the wrong ingress for MCP hosting AND made a missing
// *.t.<domain> record block an otherwise-valid single-host deployment.
// The edge is now selectable and the wildcard proof applies only to the
// edges that actually serve the tunnel namespace.
func TestSetupSingleHostEdgeNeedsNoWildcardRecord(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldLookup := setupLookupHost
	setupLookupHost = func(ctx context.Context, host string) ([]string, error) {
		// Apex resolves here; the tunnel wildcard does NOT exist.
		if strings.Contains(host, ".t.") {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []string{"203.0.113.9"}, nil
	}
	defer func() { setupLookupHost = oldLookup }()
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "TESTTOKEN")
	out := t.TempDir()
	var code int
	captured := captureOutput(t, func() {
		code = cmdSetup([]string{"--auto", "--edge", "tunnel", "--hostname", "lab.dynv6.net", "--edge", "single-host",
			"--acme-email", "ops@mailtest.invalid-test", "--out", out,
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	// Provisioning still cannot complete without root/Caddy, so the
	// outcome remains ACTION_REQUIRED - but the REASON must now be edge
	// provisioning, never the missing wildcard record.
	if code != apperr.ExitRelayTLS {
		t.Fatalf("exit=%d, want %d", code, apperr.ExitRelayTLS)
	}
	if strings.Contains(captured, "*.t.lab.dynv6.net") {
		t.Fatalf("single-host edge demanded a wildcard record:\n%s", captured)
	}
	// The rendered deployment must be the single-host edge, not the
	// wildcard tunnel namespace.
	rendered, err := os.ReadFile(filepath.Join(out, "Caddyfile"))
	if err != nil {
		t.Fatalf("deployment not rendered: %v", err)
	}
	if strings.Contains(string(rendered), "*.t.") {
		t.Fatalf("rendered the tunnel namespace instead of a single-host edge:\n%s", rendered)
	}
}

// The tunnel edge (the default) still REQUIRES the wildcard record:
// this is existing behaviour the fix must not weaken.
func TestSetupTunnelEdgeStillRequiresWildcard(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldLookup := setupLookupHost
	setupLookupHost = func(ctx context.Context, host string) ([]string, error) {
		if strings.Contains(host, ".t.") {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []string{"203.0.113.9"}, nil
	}
	defer func() { setupLookupHost = oldLookup }()
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	t.Setenv("OCLIV_DYNV6_ENDPOINT", upd.URL)
	t.Setenv("DYNV6_TOKEN", "TESTTOKEN")
	out := t.TempDir()
	var code int
	captured := captureOutput(t, func() {
		// --edge tunnel is the default and serves the tunnel namespace,
		// so it must still demand the wildcard record. (The wildcard edge
		// additionally needs a DNS plugin at init, so it is not reachable
		// from setup without one.)
		code = cmdSetup([]string{"--auto", "--edge", "tunnel", "--hostname", "lab.dynv6.net",
			"--acme-email", "ops@mailtest.invalid-test", "--out", out,
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	if code != apperr.ExitRelayTLS {
		t.Fatalf("exit=%d, want %d (wildcard unverified)", code, apperr.ExitRelayTLS)
	}
	if !strings.Contains(captured, "*.t.lab.dynv6.net") {
		t.Fatalf("wildcard edge lost its record instruction:\n%s", captured)
	}
}

func TestSetupRejectsUnknownEdge(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	if code := cmdSetup([]string{"--auto", "--edge", "cloudflare",
		"--echo-v4", echo.URL, "--echo-v6", ""}); code != apperr.ExitCLIValidation {
		t.Fatalf("exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}

// TestAutoEnrollRejectsDifferentRelay: an existing agent key bound to a
// different relay must produce an explicit conflict (exit 4), never a silent
// already-enrolled success, and the key must be preserved. Pre-fix, any
// existing key reported success regardless of which relay it belonged to.
func TestAutoEnrollRejectsDifferentRelay(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir, url := enrollFixture(t)
	keyID, code := autoEnroll(url, dir, "home")
	if code != apperr.ExitOK || keyID == "" {
		t.Fatalf("initial enroll: exit=%d key=%q", code, keyID)
	}
	other := "https://other-relay.example.test"
	var stderr bytes.Buffer
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	_, code2 := autoEnroll(other, dir, "home")
	w.Close()
	os.Stderr = origStderr
	_, _ = io.Copy(&stderr, r)
	if code2 != apperr.ExitAuth {
		t.Fatalf("different-relay re-run: exit=%d, want ExitAuth(%d)", code2, apperr.ExitAuth)
	}
	if !strings.Contains(stderr.String(), "other-relay.example.test") || !strings.Contains(stderr.String(), "refusing") {
		t.Fatalf("conflict message missing relay/refusal detail:\n%s", stderr.String())
	}
	// Key must be preserved.
	if _, err := os.Stat(filepath.Join(home, ".config", "ocliv", "agent.key")); err != nil {
		t.Fatalf("existing key was disturbed: %v", err)
	}
}

// TestAutoEnrollKeyWithoutRelayConfigBlocked: an existing key whose config
// has no relay_url cannot be verified; the command must fail closed with an
// actionable message and must not silently treat it as matching.
func TestAutoEnrollKeyWithoutRelayConfigBlocked(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir, url := enrollFixture(t)
	if _, code := autoEnroll(url, dir, "home"); code != apperr.ExitOK {
		t.Fatalf("initial enroll: %d", code)
	}
	// Erase relay_url from the config.
	cfg := filepath.Join(home, ".config", "ocliv", "config.toml")
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "relay_url") {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(cfg, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	r, w, _ := os.Pipe()
	origStderr := os.Stderr
	os.Stderr = w
	_, code := autoEnroll(url, dir, "home")
	w.Close()
	os.Stderr = origStderr
	_, _ = io.Copy(&stderr, r)
	if code != apperr.ExitAuth {
		t.Fatalf("no-relay-url re-run: exit=%d, want ExitAuth", code)
	}
	if !strings.Contains(stderr.String(), "relay_url") {
		t.Fatalf("expected actionable relay_url message, got:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "ocliv", "agent.key")); err != nil {
		t.Fatalf("key disturbed: %v", err)
	}
}
