package cli

// Slice 1 acceptance: `setup --check` against injected echo endpoints
// reports the observed egress and a path verdict without touching DNS,
// routers, services, or credentials.

import (
	"context"
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
		code = cmdSetup([]string{"--auto", "--hostname", "lab.dynv6.net", "--dry-run", "--echo-v4", echo.URL, "--echo-v6", ""})
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
		code = cmdSetup([]string{"--auto", "--hostname", "lab.dynv6.net", "--echo-v4", echo.URL, "--echo-v6", ""})
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

func TestSetupRenderPersistsOnDNSMatch(t *testing.T) {
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
		code = cmdSetup([]string{"--auto", "--hostname", "lab.dynv6.net",
			"--acme-email", "ops@mailtest.invalid-test", "--out", out,
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	// DNS (apex + wildcard) verifies in this fixture, so the fresh
	// relay_url persists — but edge provisioning cannot complete
	// without root/Caddy, so the outcome is ACTION_REQUIRED, never a
	// success claim.
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
	if err != nil {
		t.Fatalf("agent config not written: %v", err)
	}
	if !strings.Contains(string(raw), `relay_url = "https://lab.dynv6.net"`) {
		t.Fatalf("relay_url not persisted in:\n%s", raw)
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
		{"fresh persists", "", "https://lab.dynv6.net", false, true},
		{"same value idempotent", "https://lab.dynv6.net", "https://lab.dynv6.net", false, true},
		{"replacement waits for provisioning", "https://old.example", "https://lab.dynv6.net", false, false},
		{"replacement after provisioning", "https://old.example", "https://lab.dynv6.net", true, true},
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
		code = cmdSetup([]string{"--auto", "--hostname", "lab.dynv6.net",
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
		code = cmdSetup([]string{"--auto", "--hostname", "lab.dynv6.net",
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
		code = cmdSetup([]string{"--auto", "--hostname", "lab.dynv6.net",
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
