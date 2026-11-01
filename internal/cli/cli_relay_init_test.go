// Phase 1 (Domain A): `relay init` generates validated deployment files
// instead of only printing instructions. Generation never touches live
// system paths and never overwrites existing files with different
// content: re-runs are idempotent, conflicting re-runs fail closed.
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ocliv/internal/apperr"
)

func TestRelayInitRefusesPlaceholder(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	if code := cmdRelayInit([]string{"--domain", "example.com", "--out", out}); code != apperr.ExitCLIValidation {
		t.Fatalf("placeholder domain: exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("refused init still created output")
	}
}

func TestRelayInitRequiresEmailForSingleHost(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	argv := []string{"--domain", "hosting.test", "--mcp-host", "relay.hosting.test", "--out", out}
	if code := cmdRelayInit(argv); code != apperr.ExitCLIValidation {
		t.Fatalf("missing acme email: exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}

func TestRelayInitGeneratesSingleHost(t *testing.T) {
	out := t.TempDir()
	argv := []string{
		"--domain", "hosting.test",
		"--mcp-host", "relay.hosting.test",
		"--acme-email", "ops@hosting.test",
		"--data", "/var/lib/ocliv",
		"--out", out,
	}
	got := captureStdout(t, func() {
		if code := cmdRelayInit(argv); code != apperr.ExitOK {
			t.Fatalf("exit=%d", code)
		}
	})
	if !strings.Contains(got, "preparation-only") {
		t.Fatalf("init no longer labels itself preparation-only:\n%s", got)
	}
	env, err := os.ReadFile(filepath.Join(out, "relay.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"OCLIV_DOMAIN=hosting.test",
		"OCLIV_MCP_HOST=relay.hosting.test",
		"OCLIV_RELAY_HOST=relay.hosting.test",
	} {
		if !strings.Contains(string(env), want) {
			t.Fatalf("relay.env missing %q:\n%s", want, env)
		}
	}
	if fi, err := os.Stat(filepath.Join(out, "relay.env")); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("relay.env not owner-only: %v %v", fi, err)
	}
	caddy, err := os.ReadFile(filepath.Join(out, "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(caddy), "{$") {
		t.Fatalf("Caddyfile has unsubstituted placeholders:\n%s", caddy)
	}
	for _, want := range []string{"relay.hosting.test", "ops@hosting.test", "127.0.0.1:8080"} {
		if !strings.Contains(string(caddy), want) {
			t.Fatalf("Caddyfile missing %q", want)
		}
	}
	for _, f := range []string{"ocliv-relay.service", "dns-records.txt"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	// Idempotent re-run: identical content succeeds.
	if code := cmdRelayInit(argv); code != apperr.ExitOK {
		t.Fatalf("idempotent re-run: exit=%d", code)
	}
	// Conflicting re-run fails closed instead of overwriting.
	argv2 := []string{
		"--domain", "hosting.test",
		"--mcp-host", "relay.hosting.test",
		"--acme-email", "changed@hosting.test",
		"--data", "/var/lib/ocliv",
		"--out", out,
	}
	if code := cmdRelayInit(argv2); code == apperr.ExitOK {
		t.Fatal("conflicting re-run overwrote deployment files")
	}
}

func TestRelayInitCheckAcceptsGenerated(t *testing.T) {
	out := t.TempDir()
	gen := []string{
		"--domain", "hosting.test",
		"--mcp-host", "relay.hosting.test",
		"--acme-email", "ops@hosting.test",
		"--data", "/var/lib/ocliv",
		"--out", out,
	}
	if code := cmdRelayInit(gen); code != apperr.ExitOK {
		t.Fatalf("generate: exit=%d", code)
	}
	if code := cmdRelayInit([]string{"--check", "--out", out}); code != apperr.ExitOK {
		t.Fatalf("check of generated dir: exit=%d", code)
	}
}

func TestRelayInitCheckRejectsBadDir(t *testing.T) {
	// Missing files.
	if code := cmdRelayInit([]string{"--check", "--out", t.TempDir()}); code == apperr.ExitOK {
		t.Fatal("check of empty dir exited 0")
	}
	// Leftover placeholder in the Caddyfile.
	out := t.TempDir()
	gen := []string{
		"--domain", "hosting.test",
		"--mcp-host", "relay.hosting.test",
		"--acme-email", "ops@hosting.test",
		"--out", out,
	}
	if code := cmdRelayInit(gen); code != apperr.ExitOK {
		t.Fatalf("generate: exit=%d", code)
	}
	bad, err := os.ReadFile(filepath.Join(out, "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	bad = append(bad, "\n# uses {$OCLIV_HOST} again\n"...)
	if err := os.WriteFile(filepath.Join(out, "Caddyfile"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdRelayInit([]string{"--check", "--out", out}); code == apperr.ExitOK {
		t.Fatal("check with placeholder Caddyfile exited 0")
	}
}

func TestRelayInitGeneratesWildcard(t *testing.T) {
	out := t.TempDir()
	argv := []string{"--domain", "hosting-test.net", "--edge", "wildcard",
		"--dns-provider", "digitalocean", "--dns-env", "DO_TOKEN",
		"--acme-email", "ops@hosting-test.net", "--out", out}
	if code := cmdRelayInit(argv); code != apperr.ExitOK {
		t.Fatalf("exit=%d", code)
	}
	caddy, err := os.ReadFile(filepath.Join(out, "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(caddy), "{$") {
		t.Fatalf("wildcard Caddyfile has unsubstituted placeholders")
	}
	for _, want := range []string{
		"relay.hosting-test.net", "*.t.hosting-test.net",
		// The DNS-01 stanza must be ACTIVE (Round 36): a commented
		// block passes generation but can never issue the wildcard.
		"dns digitalocean {env.DO_TOKEN}",
	} {
		if !strings.Contains(string(caddy), want) {
			t.Fatalf("wildcard Caddyfile missing %q", want)
		}
	}
	dns, err := os.ReadFile(filepath.Join(out, "dns-records.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dns), "digitalocean") || !strings.Contains(string(dns), "DO_TOKEN") {
		t.Fatalf("dns-records.txt names no provider/credential env:\n%s", dns)
	}
	if code := cmdRelayInit([]string{"--check", "--out", out}); code != apperr.ExitOK {
		t.Fatalf("--check on complete wildcard dir: exit=%d", code)
	}
}

// The wildcard edge without a DNS provider is an incomplete TLS
// configuration: refuse it at generation time, creating nothing.
func TestRelayInitWildcardRequiresProvider(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	argv := []string{"--domain", "hosting-test.net", "--edge", "wildcard",
		"--acme-email", "ops@hosting-test.net", "--out", out}
	if code := cmdRelayInit(argv); code != apperr.ExitCLIValidation {
		t.Fatalf("missing --dns-provider: exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("refused init still created output")
	}
}

// Provider flags are meaningless on the single-host edge (plain ACME);
// accepting them would silently drop operator intent.
func TestRelayInitSingleHostRejectsProvider(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deploy")
	argv := []string{"--domain", "hosting.test", "--mcp-host", "relay.hosting.test",
		"--acme-email", "ops@hosting.test",
		"--dns-provider", "digitalocean", "--out", out}
	if code := cmdRelayInit(argv); code != apperr.ExitCLIValidation {
		t.Fatalf("provider on single-host: exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}

// A wildcard edge on a never-public namespace can never complete
// DNS-01. Refuse it unless the operator explicitly marks lab prep.
func TestRelayInitWildcardRefusesReserved(t *testing.T) {
	for _, domain := range []string{
		"ocliv.test", "lab.localhost", "edge.local", "corp.home.arpa",
		"example.com", "relayhost",
	} {
		out := filepath.Join(t.TempDir(), "deploy")
		argv := []string{"--domain", domain, "--edge", "wildcard",
			"--dns-provider", "digitalocean",
			"--acme-email", "ops@" + strings.TrimPrefix(domain, "relayhost"),
			"--out", out}
		// Single-label names need a syntactically valid email; the
		// domain refusal must still fire first for the others, so give
		// each case a parseable address where possible.
		if domain == "relayhost" {
			argv[5] = "ops@example.net"
		}
		if code := cmdRelayInit(argv); code != apperr.ExitCLIValidation {
			t.Fatalf("reserved %q: exit=%d, want %d", domain, code, apperr.ExitCLIValidation)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("reserved %q: refused init still created output", domain)
		}
	}
}

// The escape hatch exists for lab prep (e.g. the tailnet lab renders a
// wildcard dir for ocliv.test); it must produce a passing --check.
func TestRelayInitReservedEscapeHatch(t *testing.T) {
	out := t.TempDir()
	argv := []string{"--domain", "ocliv.test", "--edge", "wildcard",
		"--dns-provider", "digitalocean",
		"--acme-email", "ops@ocliv.test",
		"--allow-reserved-domain", "--out", out}
	if code := cmdRelayInit(argv); code != apperr.ExitOK {
		t.Fatalf("escape hatch: exit=%d", code)
	}
	if code := cmdRelayInit([]string{"--check", "--out", out}); code != apperr.ExitOK {
		t.Fatalf("--check on lab wildcard dir: exit=%d", code)
	}
	if code := cmdRelayInit([]string{"--domain", "hosting.test", "--mcp-host", "relay.hosting.test",
		"--acme-email", "ops@hosting.test", "--allow-reserved-domain",
		"--out", filepath.Join(t.TempDir(), "x")}); code != apperr.ExitCLIValidation {
		t.Fatalf("hatch on single-host: exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}

// Provider and credential names render verbatim into the Caddyfile, so
// anything outside the token shapes is rejected before writing.
func TestRelayInitRejectsMalformedProvider(t *testing.T) {
	for _, extra := range [][]string{
		{"--dns-provider", "do plugin"},
		{"--dns-provider", "dns{x}"},
		{"--dns-provider", ""},
		{"--dns-env", "DO-TOKEN"},
		{"--dns-env", "DO TOKEN"},
	} {
		out := filepath.Join(t.TempDir(), "deploy")
		argv := []string{"--domain", "hosting-test.net", "--edge", "wildcard",
			"--acme-email", "ops@hosting-test.net", "--out", out}
		argv = append(argv, extra...)
		if code := cmdRelayInit(argv); code != apperr.ExitCLIValidation {
			t.Fatalf("%q: exit=%d, want %d", extra, code, apperr.ExitCLIValidation)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%q: refused init still created output", extra)
		}
	}
}

// --check must catch a wildcard Caddyfile whose DNS-01 stanza was
// commented out by hand after generation, and any staging marker that
// would silently downgrade a public deployment to lab trust.
func TestRelayInitCheckCatchesDeadStanza(t *testing.T) {
	out := t.TempDir()
	argv := []string{"--domain", "hosting-test.net", "--edge", "wildcard",
		"--dns-provider", "digitalocean",
		"--acme-email", "ops@hosting-test.net", "--out", out}
	if code := cmdRelayInit(argv); code != apperr.ExitOK {
		t.Fatalf("setup exit=%d", code)
	}
	raw, err := os.ReadFile(filepath.Join(out, "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	commented := strings.Replace(string(raw),
		"dns digitalocean {env.DNS_API_TOKEN}",
		"# dns digitalocean {env.DNS_API_TOKEN}", 1)
	// NOTE: default dns-env is DNS_API_TOKEN; the stanza above uses it.
	if !strings.Contains(commented, "# dns digitalocean") {
		t.Skip("template shape changed; rewrite this negative control")
	}
	if err := os.WriteFile(filepath.Join(out, "Caddyfile"), []byte(commented), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdRelayInit([]string{"--check", "--out", out}); code == apperr.ExitOK {
		t.Fatal("--check passed a Caddyfile with commented DNS-01 stanza")
	}
	lab := strings.Replace(string(raw), "tls {", "tls internal # lab\n\ttls {", 1)
	if err := os.WriteFile(filepath.Join(out, "Caddyfile"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdRelayInit([]string{"--check", "--out", out}); code == apperr.ExitOK {
		t.Fatal("--check passed a Caddyfile carrying a staging marker")
	}
}

func TestRelayInitRejectsMalformedEmail(t *testing.T) {
	for _, email := range []string{
		"",
		"no-at-sign",
		"two@@signs.test",
		"@hosting.test",
		"ops@",
		"op s@hosting.test",
		"ops@hosting.test\ntls internal",
		"ops@hosting.test; rm -rf /",
		"ops@host ing.test",
		"op$s@hosting.test",
		"ops@exam_ple.test",
	} {
		out := filepath.Join(t.TempDir(), "deploy")
		argv := []string{"--domain", "hosting.test", "--acme-email", email, "--out", out}
		if code := cmdRelayInit(argv); code != apperr.ExitCLIValidation {
			t.Fatalf("email %q: exit=%d, want %d", email, code, apperr.ExitCLIValidation)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("email %q: refused init still created output", email)
		}
	}
}

func TestRelayInitRefusesSymlinkOut(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "deploy")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	argv := []string{"--domain", "hosting.test", "--acme-email", "ops@hosting.test", "--out", link}
	if code := cmdRelayInit(argv); code == apperr.ExitOK {
		t.Fatal("init into symlinked --out exited 0")
	}
}

func TestRelayInitRefusesSymlinkTarget(t *testing.T) {
	out := t.TempDir()
	target := filepath.Join(out, "deploy")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	// Point one expected output at an unrelated file via symlink.
	victim := filepath.Join(out, "victim.txt")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(target, "Caddyfile")); err != nil {
		t.Fatal(err)
	}
	argv := []string{"--domain", "hosting.test", "--acme-email", "ops@hosting.test", "--out", target}
	if code := cmdRelayInit(argv); code == apperr.ExitOK {
		t.Fatal("init over symlinked target exited 0")
	}
	if raw, err := os.ReadFile(victim); err != nil || string(raw) != "precious" {
		t.Fatalf("symlink target followed: victim=%q err=%v", raw, err)
	}
}
