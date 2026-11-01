package cli

// Launcher contract tests (P0-B): the systemd launcher must refuse to
// start without OCLIV_DOMAIN and must pass --mcp-host only when
// OCLIV_MCP_HOST is non-empty. An explicitly empty --mcp-host= fails CLI
// validation, so unconditional flag passing would break relays that do
// not configure MCP ingress.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const launchScript = "../../packaging/systemd/ocliv-relay-launch.sh"

func launchEnv(t *testing.T, bin string, domain, mcpHost string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sh", launchScript)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "OCLIV_BIN=" + bin}
	if domain != "" {
		cmd.Env = append(cmd.Env, "OCLIV_DOMAIN="+domain)
	}
	if mcpHost != "" {
		cmd.Env = append(cmd.Env, "OCLIV_MCP_HOST="+mcpHost)
	}
	return cmd
}

func TestLaunchRefusesWithoutDomain(t *testing.T) {
	if out, err := launchEnv(t, "/bin/true", "", "").CombinedOutput(); err == nil {
		t.Fatalf("launcher started without OCLIV_DOMAIN: %q", out)
	}
}

func TestLaunchOmitsEmptyMCPHost(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "args")
	bin := filepath.Join(t.TempDir(), "bin.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + probe + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := launchEnv(t, bin, "ocliv.test", "").CombinedOutput(); err != nil {
		t.Fatalf("launcher failed without MCP host: %v %q", err, out)
	}
	raw, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(arg, "--mcp-host") {
			t.Fatalf("launcher passed %q with OCLIV_MCP_HOST unset", arg)
		}
	}
}

func TestLaunchPassesConfiguredMCPHost(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "args")
	bin := filepath.Join(t.TempDir(), "bin.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + probe + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := launchEnv(t, bin, "ocliv.test", "relay.example.org").CombinedOutput(); err != nil {
		t.Fatalf("launcher failed with MCP host: %v %q", err, out)
	}
	raw, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "--mcp-host=relay.example.org") {
		t.Fatalf("launcher dropped configured MCP host: %q", raw)
	}
}
