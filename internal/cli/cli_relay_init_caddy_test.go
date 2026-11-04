package cli

// Real-Caddy gate for `relay init --check`: structural checks alone
// cannot catch a broken Caddyfile. When a caddy binary is on PATH,
// `caddy validate` is authoritative; its failure fails the check.
// The indirection (initCaddyValidate) is stubbed so the proof needs
// no live Caddy; a second case pins that an ABSENT caddy binary
// skips to structural-only instead of failing.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ocliv/internal/apperr"
)

func generateSingleHost(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "deploy")
	argv := []string{"--domain", "hosting.test", "--mcp-host", "relay.hosting.test",
		"--acme-email", "op@hosting.test", "--out", out}
	if code := cmdRelayInit(argv); code != apperr.ExitOK {
		t.Fatalf("cmdRelayInit generate: exit %d", code)
	}
	return out
}

func TestRelayInitCheckFailsOnRealCaddyError(t *testing.T) {
	out := generateSingleHost(t)
	orig := initCaddyValidate
	defer func() { initCaddyValidate = orig }()
	called := false
	initCaddyValidate = func(path string) error {
		called = true
		if filepath.Base(path) != "Caddyfile" {
			t.Errorf("validate target %q want Caddyfile", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("validate target missing: %v", err)
		}
		return errors.New("syntax error: bogus directive")
	}
	// Ensure the caddy-present branch runs: stub LookPath by putting a
	// fake caddy on PATH.
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "caddy"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if code := cmdRelayInit([]string{"--check", "--out", out}); code == apperr.ExitOK {
		t.Fatal("check passed despite caddy validate failure")
	}
	if !called {
		t.Fatal("initCaddyValidate was not invoked")
	}
}

func TestRelayInitCheckSkipsCaddyWhenAbsent(t *testing.T) {
	out := generateSingleHost(t)
	orig := initCaddyValidate
	defer func() { initCaddyValidate = orig }()
	initCaddyValidate = func(path string) error {
		t.Error("initCaddyValidate must not run without a caddy binary")
		return errors.New("must not be called")
	}
	// Empty PATH (plus the temp dir): no caddy resolvable.
	t.Setenv("PATH", t.TempDir())
	if code := cmdRelayInit([]string{"--check", "--out", out}); code != apperr.ExitOK {
		t.Fatalf("check with no caddy binary: exit %d want OK", code)
	}
	if !strings.Contains(out, "deploy") {
		t.Fatalf("unexpected out dir %q", out)
	}
}
