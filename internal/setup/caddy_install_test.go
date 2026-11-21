package setup

import (
	"strings"
	"testing"
)

func TestCaddyDownloadURLPinsVersionAndModule(t *testing.T) {
	u := caddyDownloadURL("linux", "arm64", "cloudflare")
	if !strings.Contains(u, "idempotency="+PinnedCaddyVersion) {
		t.Fatalf("missing pinned Caddy version in URL: %s", u)
	}
	if !strings.Contains(u, "github.com%2Fcaddy-dns%2Fcloudflare%40v") {
		t.Fatalf("missing pinned cloudflare module version in URL: %s", u)
	}
	if DefaultCaddyBinaryPath == "/usr/bin/caddy" || DefaultCaddyBinaryPath == "/usr/local/bin/caddy" {
		t.Fatalf("DefaultCaddyBinaryPath=%q must be an Ocliv-owned path, not distro/shared bin", DefaultCaddyBinaryPath)
	}
}
