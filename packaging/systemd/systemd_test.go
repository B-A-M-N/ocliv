package systemd

import (
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
		"OnUnitActiveSec=",
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
