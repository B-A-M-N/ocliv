package install_test

// Installer input validation (Round 13): DOMAIN/MCP_HOST/RELAY_HOST are
// written raw into relay.env and word-split into the launch command, so
// install.sh must reject malformed hostnames before replacing anything.
// This test extracts valid_host() from the real script and runs the
// accept/reject matrix against it, plus a syntax gate on the script.

import (
	"os/exec"
	"strings"
	"testing"
)

// runValidHost extracts valid_host() from install.sh into a temp file,
// sources it in a fresh shell, and reports whether it accepts h.
func runValidHost(t *testing.T, h string) bool {
	t.Helper()
	out, err := exec.Command("sh", "-c", `
set -eu
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed -n '/^valid_host/,/^}/p' install.sh > "$tmp"
LC_ALL=C
. "$tmp"
valid_host "$1"
`, "sh", h).CombinedOutput()
	_ = out
	return err == nil
}

func TestInstallValidHostMatrix(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	accept := []string{
		"relay.example.net", "ocliv.test", "a-b.c-d.example.net.",
		"localhost", "x", "foo.",
	}
	for _, h := range accept {
		if !runValidHost(t, h) {
			t.Errorf("valid_host wrongly rejected %q", h)
		}
	}
	reject := []string{
		"", ".foo", "-foo", "foo-", "--x", "fo..o",
		"foo bar", "a;b", "foo_.com", "a\nb=1",
	}
	for _, h := range reject {
		if runValidHost(t, h) {
			t.Errorf("valid_host wrongly accepted %q", h)
		}
	}
}

func TestInstallScriptSyntax(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	out, err := exec.Command("sh", "-n", "install.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("sh -n install.sh: %v: %s", err, out)
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		t.Fatalf("unexpected sh -n output: %q", s)
	}
}
