package cli

// Slice 1 acceptance: `setup --check` against injected echo endpoints
// reports the observed egress and a path verdict without touching DNS,
// routers, services, or credentials.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ocliv/internal/apperr"
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
	_ = captureStdout(t, func() {
		code = cmdSetup([]string{"--auto", "--hostname", "lab.dynv6.net",
			"--acme-email", "ops@mailtest.invalid-test", "--out", out,
			"--echo-v4", echo.URL, "--echo-v6", ""})
	})
	if code != apperr.ExitOK {
		t.Fatalf("exit=%d", code)
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

func TestSetupRejectsUnknownFlag(t *testing.T) {
	if code := cmdSetup([]string{"--bogus"}); code != apperr.ExitCLIValidation {
		t.Fatalf("exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}
