package cli

import (
	"testing"
)

// The managed authorization mode must map to a real relay access mode and a
// real ingress profile; a typo here would publish an unenforceable route.
func TestMCPManagedAccessMode(t *testing.T) {
	if got := mcpAccessMode("ocliv-managed"); got != "mcp_managed_oauth" {
		t.Fatalf("mcpAccessMode(ocliv-managed) = %q, want mcp_managed_oauth", got)
	}
	if got := mcpAuthProfiles["ocliv-managed"]; got != "managed-oauth" {
		t.Fatalf("mcpAuthProfiles[ocliv-managed] = %q, want managed-oauth", got)
	}
	// The existing modes must be unchanged.
	if got := mcpAccessMode("upstream-oauth"); got != "mcp_upstream_oauth" {
		t.Fatalf("mcpAccessMode(upstream-oauth) = %q, want mcp_upstream_oauth", got)
	}
	if got := mcpAccessMode("fixture-anonymous"); got != "mcp_anonymous_fixture" {
		t.Fatalf("mcpAccessMode(fixture-anonymous) = %q, want mcp_anonymous_fixture", got)
	}
}

// A managed publication is a first-class publish: it must parse, and it must
// never require an upstream OAuth discovery file.
func TestParseMCPPublishManagedAccepted(t *testing.T) {
	cfg, code := parseMCPPublish([]string{
		"--local=http://127.0.0.1:8765/mcp", "--auth=ocliv-managed",
	}, false)
	if code != 0 {
		t.Fatalf("managed publish rejected: code %d", code)
	}
	if cfg.auth != "ocliv-managed" {
		t.Fatalf("cfg.auth = %q, want ocliv-managed", cfg.auth)
	}
}

// Managed mode must not inherit the upstream-only flags; they are rejected
// rather than silently ignored so the operator learns the mode boundary.
func TestParseMCPPublishManagedRejectsUpstreamFlags(t *testing.T) {
	for _, argv := range [][]string{
		{"--local=http://127.0.0.1:1/mcp", "--auth=ocliv-managed", "--strict-discovery"},
		{"--local=http://127.0.0.1:1/mcp", "--auth=ocliv-managed", "--dev-allow-unverified-discovery"},
		{"--local=http://127.0.0.1:1/mcp", "--auth=ocliv-managed", "--resource-file=/tmp/x"},
	} {
		if _, code := parseMCPPublish(argv, false); code == 0 {
			t.Errorf("argv %q accepted, want rejection", argv)
		}
	}
}

// The operator authz command set is closed: unknown subcommands fail closed.
// Reads and key rotation on an empty store are legitimate successes (an
// empty store is valid; rotation creates the issuer); only a mutating
// command with a missing client and an unknown subcommand must fail.
func TestAuthzCommandSetClosed(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"pending", "list"} {
		if code := cmdAuthz([]string{sub, "--data", dir}); code != 0 {
			t.Errorf("authz %s on an empty data dir returned %d, want 0", sub, code)
		}
	}
	if code := cmdAuthz([]string{"rotate-key", "--data", dir}); code != 0 {
		t.Errorf("authz rotate-key on an empty data dir returned %d, want 0", code)
	}
	if code := cmdAuthz([]string{"exec", "--data", dir}); code == 0 {
		t.Error("authz exec accepted, want rejection")
	}
	if code := cmdAuthz(nil); code == 0 {
		t.Error("authz with no subcommand returned 0, want failure")
	}
}

// stdio publication is accepted ONLY with relay-terminated managed
// authorization: the adapter has no upstream OAuth to verify, so
// upstream-oauth cannot be proven for it and fixture-anonymous must never
// bound an arbitrary child.
func TestParseMCPPublishStdioManagedOnly(t *testing.T) {
	cfg, code := parseMCPPublish([]string{
		"--stdio", "--auth=ocliv-managed", "--", "/bin/srv", "--flag",
	}, false)
	if code != 0 {
		t.Fatalf("stdio managed publish rejected: code %d", code)
	}
	if !cfg.stdio || cfg.auth != "ocliv-managed" {
		t.Fatalf("cfg = %+v, want stdio+managed", cfg)
	}
	if len(cfg.cmd) != 2 || cfg.cmd[0] != "/bin/srv" {
		t.Fatalf("cfg.cmd = %v, want the operator command", cfg.cmd)
	}
	for _, auth := range []string{"upstream-oauth", "fixture-anonymous", ""} {
		argv := []string{"--stdio", "--auth=" + auth, "--", "/bin/srv"}
		if auth == "" {
			argv = []string{"--stdio", "--", "/bin/srv"}
		}
		if _, code := parseMCPPublish(argv, false); code == 0 {
			t.Errorf("stdio publish accepted with auth %q, want rejection", auth)
		}
	}
	if _, code := parseMCPPublish([]string{"--stdio", "--auth=ocliv-managed"}, false); code == 0 {
		t.Error("stdio publish without a command accepted, want rejection")
	}
	// serve mode has no route, so stdio serve stays rejected.
	if _, code := parseMCPPublish([]string{"--stdio", "--auth=ocliv-managed", "--", "/bin/srv"}, true); code == 0 {
		t.Error("stdio serve accepted, want rejection")
	}
}

// approve/revoke require --client; a missing client must fail validation
// before any store access.
func TestAuthzClientRequired(t *testing.T) {
	if code := cmdAuthzApprove([]string{"--data", t.TempDir()}); code == 0 {
		t.Error("approve without --client returned 0, want failure")
	}
	if code := cmdAuthzRevoke([]string{"--data", t.TempDir()}); code == 0 {
		t.Error("revoke without --client returned 0, want failure")
	}
}
