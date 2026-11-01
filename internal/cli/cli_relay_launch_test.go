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
	return launchEnvRelay(t, bin, domain, mcpHost, "")
}

// launchEnvRelay adds the optional OCLIV_RELAY_HOST override: Funnel's
// *.ts.net hostname must match the control authority as well as the MCP
// authority, while ordinary relays keep the relay.<domain> default.
func launchEnvRelay(t *testing.T, bin string, domain, mcpHost, relayHost string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sh", launchScript)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "OCLIV_BIN=" + bin}
	if domain != "" {
		cmd.Env = append(cmd.Env, "OCLIV_DOMAIN="+domain)
	}
	if mcpHost != "" {
		cmd.Env = append(cmd.Env, "OCLIV_MCP_HOST="+mcpHost)
	}
	if relayHost != "" {
		cmd.Env = append(cmd.Env, "OCLIV_RELAY_HOST="+relayHost)
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
	if out, err := launchEnv(t, bin, "ocliv.test", "relay.hosting.test").CombinedOutput(); err != nil {
		t.Fatalf("launcher failed with MCP host: %v %q", err, out)
	}
	raw, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "--mcp-host=relay.hosting.test") {
		t.Fatalf("launcher dropped configured MCP host: %q", raw)
	}
}

func TestLaunchPassesConfiguredRelayHost(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "args")
	bin := filepath.Join(t.TempDir(), "bin.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + probe + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := launchEnvRelay(t, bin, "ocliv.test", "funnel-host.ts.net", "funnel-host.ts.net").CombinedOutput(); err != nil {
		t.Fatalf("launcher failed with relay host: %v %q", err, out)
	}
	raw, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "--relay-host=funnel-host.ts.net") {
		t.Fatalf("launcher dropped configured relay host: %q", raw)
	}
}

func TestLaunchPassesConfiguredMCPPort(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "args")
	bin := filepath.Join(t.TempDir(), "bin.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + probe + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := launchEnvRelay(t, bin, "ocliv.test", "relay.hosting.test", "")
	cmd.Env = append(cmd.Env, "OCLIV_MCP_PORT=8444")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("launcher failed with MCP port: %v %q", err, out)
	}
	raw, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "--mcp-port=8444") {
		t.Fatalf("launcher dropped configured MCP port: %q", raw)
	}
}

func TestLaunchOmitsEmptyRelayHost(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "args")
	bin := filepath.Join(t.TempDir(), "bin.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + probe + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := launchEnvRelay(t, bin, "ocliv.test", "", "").CombinedOutput(); err != nil {
		t.Fatalf("launcher failed without relay host: %v %q", err, out)
	}
	raw, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(arg, "--relay-host") {
			t.Fatalf("launcher passed %q with OCLIV_RELAY_HOST unset", arg)
		}
	}
}
