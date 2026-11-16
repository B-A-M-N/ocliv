package systemd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Task 5: the unattended DNS-refresh pair must be safe by
// construction. These assertions validate the shipped unit files
// without installing anything: DNS-only refresh, credential from a
// restricted file (never argv), no overlap, no relay/Caddy restart,
// logs to the journal, ordinary clients unaffected (no systemd
// requirement in the client path).
func assertRefreshService(t *testing.T, unit string) {
	t.Helper()
	for _, want := range []string{
		"Type=oneshot",
		"setup --refresh-dns",
		"--token-file=",
		"EnvironmentFile=/etc/ocliv/dns-refresh.env",
		"User=ocliv",
		"StandardOutput=journal",
		"TimeoutStartSec=",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("refresh service missing %q in:\n%s", want, unit)
		}
	}
	for _, forbidden := range []string{
		"systemctl restart",
		"systemctl reload",
		"caddy reload",
		"DYNV6_TOKEN=",
		"--token=",
		"Restart=always",
		"Restart=on-failure",
	} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("refresh service must not contain %q in:\n%s", forbidden, unit)
		}
	}
}

func TestDNSRefreshUnits(t *testing.T) {
	svc := RefreshService()
	assertRefreshService(t, svc)
	timer := RefreshTimer()
	for _, want := range []string{
		"OnUnitActiveSec=15min",
		"WantedBy=timers.target",
	} {
		if !strings.Contains(timer, want) {
			t.Fatalf("refresh timer missing %q in:\n%s", want, timer)
		}
	}
	if strings.Contains(timer, "WantedBy=multi-user.target") {
		t.Fatal("refresh timer must be timer-activated, not boot-activated as a service")
	}
}

func TestPublisherUnitsShareSupervisionContract(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Dir(source)
	units := []string{
		filepath.Join(root, "ocliv-mcp-publisher.service"),
		filepath.Join(root, "ocliv-publisher@.service"),
		filepath.Join(root, "..", "mcp", "systemd", "ocliv-publisher.service"),
	}
	for _, path := range units {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read publisher unit %s: %v", path, err)
		}
		unit := string(raw)
		for _, want := range []string{
			"OCLIV_LOCAL_URL",
			"OCLIV_AUTH",
			"OCLIV_NAME",
			"OCLIV_TTL",
			"OCLIV_RESOURCE_FILE",
			"Restart=on-failure",
			"RestartPreventExitStatus=2 4 6 7",
			"RestartSec=30",
			"stays registered",
			"mcp unpublish",
			"OCLIV_STRICT and OCLIV_RESOURCE_FILE are only valid with upstream-oauth",
			"unsupported OCLIV_AUTH",
		} {
			if !strings.Contains(unit, want) {
				t.Errorf("%s lacks shared publisher contract field %q", path, want)
			}
		}
		if start := strings.Index(unit, "ExecStart="); start < 0 {
			t.Errorf("%s has no supervised ExecStart", path)
		} else {
			execStart := unit[start:]
			if end := strings.Index(execStart, "\nWorkingDirectory="); end >= 0 {
				execStart = execStart[:end]
			}
			if end := strings.Index(execStart, "\nRestart="); end >= 0 {
				execStart = execStart[:end]
			}
			if strings.Contains(execStart, "mcp unpublish") {
				t.Errorf("%s permanently unpublishes during supervised startup", path)
			}
		}
		if !strings.Contains(unit, "User=ocliv-publisher") || !strings.Contains(unit, "Group=ocliv-publisher") {
			t.Errorf("%s must run as unprivileged ocliv-publisher user/group", path)
		}
		if !strings.Contains(unit, "InaccessiblePaths=/var/lib/ocliv") {
			t.Errorf("%s must mark /var/lib/ocliv inaccessible", path)
		}
		homeStore := "/home/ocliv-publisher/.config/ocliv"
		hasHomeWrite := false
		for _, line := range strings.Split(unit, "\n") {
			if paths, ok := strings.CutPrefix(line, "ReadWritePaths="); ok {
				for _, p := range strings.Fields(paths) {
					if p == "/var/lib/ocliv" {
						t.Errorf("%s must NOT grant ReadWritePaths to relay state /var/lib/ocliv", path)
					}
					if p == homeStore {
						hasHomeWrite = true
					}
				}
			}
		}
		if strings.Contains(unit, "ProtectHome=true") || !hasHomeWrite {
			t.Errorf("%s blocks the home-scoped enrollment store required by the publisher", path)
		}
		if strings.Contains(path, "ocliv-publisher") && !strings.Contains(unit, "StateDirectory=ocliv-publisher") {
			t.Errorf("%s does not provision its resource-file state directory", path)
		}
	}
	envPath := filepath.Join(root, "ocliv-mcp-publisher.env.example")
	env, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read publisher environment example: %v", err)
	}
	for _, want := range []string{"OCLIV_LOCAL_URL=", "OCLIV_AUTH=", "OCLIV_NAME=", "OCLIV_TTL=", "OCLIV_RESOURCE_FILE="} {
		if !strings.Contains(string(env), want) {
			t.Errorf("publisher environment example lacks %q", want)
		}
	}
	if !strings.Contains(string(env), "OCLIV_AUTH=ocliv-managed") || !strings.Contains(string(env), "OCLIV_STRICT=\n") {
		t.Fatal("managed-OAuth example must select managed auth and leave upstream-only discovery flags unset")
	}
	duplicateEnv, err := os.ReadFile(filepath.Join(root, "..", "mcp", "config", "publisher.env.example"))
	if err != nil {
		t.Fatalf("read duplicate publisher environment example: %v", err)
	}
	if !strings.Contains(string(duplicateEnv), "OCLIV_RESOURCE_FILE=") || strings.Contains(string(duplicateEnv), "MCP_BINDING_FILE=") {
		t.Fatalf("duplicate publisher env example does not match systemd variable: %s", duplicateEnv)
	}
}
