// Relay deployment generation (Phase 1, Domain A): `relay init` validates
// its inputs and writes a ready-to-review deployment directory — relay
// environment, edge Caddyfile, systemd unit, and DNS records. It never
// touches live system paths (/etc, /usr/local, /var/lib) and never
// activates anything: the operator reviews, copies, and starts. That is
// why init keeps its "preparation-only" label even while generating.
//
// Safety rules: placeholder/empty domains refuse before anything is
// written; single-host edges require an explicit MCP hostname and ACME
// email; re-runs are idempotent (identical content succeeds) but a
// conflicting re-run fails closed instead of overwriting.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ocliv/internal/apperr"
	edgecaddy "ocliv/packaging/caddy"
	edgesystemd "ocliv/packaging/systemd"
)

// initFileTargets names every file init may write, for the
// no-clobber check and operator reporting.
var initFileTargets = []string{"relay.env", "Caddyfile", "ocliv-relay.service", "dns-records.txt"}

type initConfig struct {
	domain    string
	mcpHost   string
	acmeEmail string
	dataDir   string
	outDir    string
	edge      string
	checkOnly bool
	// dnsProvider names the Caddy DNS plugin module used for wildcard
	// DNS-01 issuance (e.g. cloudflare, digitalocean, route53, rfc2136).
	// dnsEnv is the environment variable Caddy reads the provider
	// credential from at runtime; it is never written into the files.
	// allowReserved permits RFC-reserved/never-public domains on the
	// wildcard edge for lab prep; without it such a deployment is
	// refused because public DNS-01 can never complete.
	dnsProvider   string
	dnsEnv        string
	allowReserved bool
}

func parseRelayInit(argv []string) (initConfig, int) {
	c := initConfig{edge: "single-host"}
	_, dataDir, _ := relayFlags(argv)
	c.dataDir = dataDir
	usage := "usage: ocliv relay init --domain DOMAIN [--mcp-host HOST] [--acme-email ADDR] [--edge single-host|wildcard|tunnel] [--dns-provider NAME [--dns-env VAR]] [--allow-reserved-domain] [--data DIR] [--out DIR]\n       ocliv relay init --check --out DIR"
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--check":
			c.checkOnly = true
		case strings.HasPrefix(a, "--domain="):
			c.domain = strings.TrimPrefix(a, "--domain=")
		case a == "--domain" && i+1 < len(argv):
			i++
			c.domain = argv[i]
		case strings.HasPrefix(a, "--mcp-host="):
			c.mcpHost = strings.TrimPrefix(a, "--mcp-host=")
		case a == "--mcp-host" && i+1 < len(argv):
			i++
			c.mcpHost = argv[i]
		case strings.HasPrefix(a, "--acme-email="):
			c.acmeEmail = strings.TrimPrefix(a, "--acme-email=")
		case a == "--acme-email" && i+1 < len(argv):
			i++
			c.acmeEmail = argv[i]
		case strings.HasPrefix(a, "--edge="):
			c.edge = strings.TrimPrefix(a, "--edge=")
		case a == "--edge" && i+1 < len(argv):
			i++
			c.edge = argv[i]
		case strings.HasPrefix(a, "--out="):
			c.outDir = strings.TrimPrefix(a, "--out=")
		case a == "--out" && i+1 < len(argv):
			i++
			c.outDir = argv[i]
		case strings.HasPrefix(a, "--dns-provider="):
			c.dnsProvider = strings.TrimPrefix(a, "--dns-provider=")
		case a == "--dns-provider" && i+1 < len(argv):
			i++
			c.dnsProvider = argv[i]
		case strings.HasPrefix(a, "--dns-env="):
			c.dnsEnv = strings.TrimPrefix(a, "--dns-env=")
		case a == "--dns-env" && i+1 < len(argv):
			i++
			c.dnsEnv = argv[i]
		case a == "--allow-reserved-domain":
			c.allowReserved = true
		case a == "--data" && i+1 < len(argv):
			i++
		case strings.HasPrefix(a, "--data=") || strings.HasPrefix(a, "--listen=") || a == "--listen":
		default:
			fmt.Fprintln(os.Stderr, usage)
			return c, apperr.ExitCLIValidation
		}
	}
	if c.outDir == "" {
		c.outDir = "./ocliv-relay-deploy"
	}
	if c.checkOnly {
		return c, apperr.ExitOK
	}
	var err error
	if c.domain, err = parseRelayDomain(c.domain); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return c, apperr.ExitCLIValidation
	}
	if c.edge != "single-host" && c.edge != "wildcard" && c.edge != "tunnel" {
		fmt.Fprintln(os.Stderr, "error: --edge must be single-host, wildcard, or tunnel")
		return c, apperr.ExitCLIValidation
	}
	if c.mcpHost != "" {
		if c.mcpHost, err = parseMCPHost(c.mcpHost); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return c, apperr.ExitCLIValidation
		}
	}
	if (c.edge == "single-host" || c.edge == "tunnel") && c.mcpHost == "" {
		fmt.Fprintln(os.Stderr, "error: --edge "+c.edge+" requires --mcp-host HOST (the one public apex hostname)")
		return c, apperr.ExitCLIValidation
	}
	// A wildcard certificate can only be issued via DNS-01, so the
	// wildcard edge must name its DNS plugin now — never ship a
	// Caddyfile whose issuance path is still a commented placeholder.
	// The single-host and tunnel edges use plain ACME/on-demand and
	// take no provider flags.
	if c.edge != "wildcard" && (c.dnsProvider != "" || c.dnsEnv != "") {
		fmt.Fprintln(os.Stderr, "error: --dns-provider/--dns-env apply only to --edge wildcard")
		return c, apperr.ExitCLIValidation
	}
	if c.edge == "wildcard" {
		if c.dnsProvider == "" {
			fmt.Fprintln(os.Stderr, "error: --edge wildcard requires --dns-provider NAME (Caddy DNS plugin for DNS-01 issuance)")
			return c, apperr.ExitCLIValidation
		}
		if err := validateDNSPluginName(c.dnsProvider); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return c, apperr.ExitCLIValidation
		}
		if c.dnsEnv == "" {
			c.dnsEnv = "DNS_API_TOKEN"
		}
		if err := validateDNSEnvName(c.dnsEnv); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return c, apperr.ExitCLIValidation
		}
		if !c.allowReserved {
			if tld := reservedPublicTLDSuffix(c.domain); tld != "" {
				fmt.Fprintf(os.Stderr, "error: --edge wildcard with %q can never complete public DNS-01 (reserved %q); use a public domain or pass --allow-reserved-domain for lab prep\n", c.domain, tld)
				return c, apperr.ExitCLIValidation
			}
		}
	} else if c.allowReserved {
		fmt.Fprintln(os.Stderr, "error: --allow-reserved-domain applies only to --edge wildcard")
		return c, apperr.ExitCLIValidation
	}
	// ACME needs a contact address on both edges; the wildcard edge
	// additionally needs manual DNS-01 provider configuration.
	if addr, err := parseACMEEmail(c.acmeEmail); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return c, apperr.ExitCLIValidation
	} else {
		c.acmeEmail = addr
	}
	return c, apperr.ExitOK
}

// validateDNSPluginName keeps the DNS-01 provider module out of the
// Caddyfile injection class: it must be a plain module token, since it
// is rendered verbatim into the tls/dns stanza.
func validateDNSPluginName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("invalid --dns-provider %q: must be a Caddy DNS plugin module name", name)
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		ok := b == '_' || b == '.' || b == '-' ||
			b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
			i > 0 && b >= '0' && b <= '9'
		if !ok {
			return fmt.Errorf("invalid --dns-provider %q: must be a Caddy DNS plugin module name", name)
		}
	}
	return nil
}

// validateDNSEnvName keeps the credential variable a plain shell name so
// the rendered {env.VAR} reference cannot escape into Caddyfile syntax.
func validateDNSEnvName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("invalid --dns-env %q: must be a shell environment variable name", name)
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '_' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || i > 0 && b >= '0' && b <= '9' {
			continue
		}
		return fmt.Errorf("invalid --dns-env %q: must be a shell environment variable name", name)
	}
	return nil
}

// reservedPublicTLDSuffix reports the reserved suffix that makes public
// DNS-01 impossible for domain (RFC 2606/6761/8375 and IANA reserved
// names), or "" when the domain is publicly plausible. Single-label
// names are never publicly issuable either.
func reservedPublicTLDSuffix(domain string) string {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if !strings.Contains(d, ".") {
		return d
	}
	for _, r := range []string{
		".test", ".localhost", ".invalid", ".example", ".local",
		".home.arpa", ".example.com", ".example.net", ".example.org",
	} {
		if strings.HasSuffix(d, r) {
			return r
		}
	}
	return ""
}

// parseACMEEmail validates the ACME contact address before it is
// rendered into the generated Caddyfile. The value must be a single
// printable token of the form local@domain: control characters,
// whitespace, and shell metacharacters are rejected so a hostile or
// mistyped address cannot inject extra Caddyfile directives or break
// the trusted-edge contract. The domain part follows the same
// hostname rules as --domain.
func parseACMEEmail(addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("--acme-email ADDR is required for ACME issuance")
	}
	for _, r := range addr {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("--acme-email %q contains control characters", addr)
		}
	}
	if strings.ContainsAny(addr, " \t\"'\\;|&$`(){}<>!#") {
		return "", fmt.Errorf("--acme-email %q contains forbidden characters", addr)
	}
	parts := strings.Split(addr, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("--acme-email %q must be of the form local@domain", addr)
	}
	for i := 0; i < len(parts[0]); i++ {
		if !isEmailLocalByte(parts[0][i]) {
			return "", fmt.Errorf("--acme-email %q has an invalid local part", addr)
		}
	}
	if _, err := parseHostname(parts[1], "--acme-email"); err != nil {
		return "", err
	}
	return addr, nil
}

func isEmailLocalByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '.', '_', '%', '+', '-':
		return true
	}
	return false
}

// writeInitFile creates path with perm, refusing to overwrite different
// content: identical re-runs succeed, conflicting ones fail closed.
// Symlinks are never followed: a symlinked target or out directory is
// refused so init cannot be redirected at an unrelated path. Writes go
// through a temp file plus rename so a crash cannot leave a torn
// half-written deployment file; --check detects a directory that was
// only partially generated.
func writeInitFile(path, content string, perm os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to follow symlink %s", path)
		}
		if raw, err := os.ReadFile(path); err == nil {
			if string(raw) == content {
				return nil
			}
			return fmt.Errorf("refusing to overwrite %s (remove it or use a fresh --out)", path)
		} else {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".init-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

// buildInitFiles renders every deployment file for cfg. Templates come
// from the embedded packaging sources so the binary is self-contained.
func buildInitFiles(cfg initConfig) map[string]string {
	files := map[string]string{}
	var env strings.Builder
	fmt.Fprintf(&env, "OCLIV_DOMAIN=%s\n", cfg.domain)
	if cfg.edge == "single-host" {
		// One public hostname serves control, unlock, and MCP routes.
		fmt.Fprintf(&env, "OCLIV_RELAY_HOST=%s\n", cfg.mcpHost)
		fmt.Fprintf(&env, "OCLIV_MCP_HOST=%s\n", cfg.mcpHost)
	} else if cfg.mcpHost != "" {
		fmt.Fprintf(&env, "OCLIV_MCP_HOST=%s\n", cfg.mcpHost)
	}
	files["relay.env"] = env.String()
	caddy := edgecaddy.SingleHost()
	if cfg.edge == "wildcard" {
		caddy = edgecaddy.Wildcard()
	} else if cfg.edge == "tunnel" {
		caddy = edgecaddy.TunnelOnDemand()
	}
	host := cfg.mcpHost
	if host == "" {
		host = "relay." + cfg.domain
	}
	caddy = strings.ReplaceAll(caddy, "{$OCLIV_HOST}", host)
	caddy = strings.ReplaceAll(caddy, "{$OCLIV_DOMAIN}", cfg.domain)
	caddy = strings.ReplaceAll(caddy, "{$OCLIV_ACME_EMAIL}", cfg.acmeEmail)
	caddy = strings.ReplaceAll(caddy, "{$OCLIV_DNS_PROVIDER}", cfg.dnsProvider)
	caddy = strings.ReplaceAll(caddy, "{$OCLIV_DNS_ENV}", cfg.dnsEnv)
	files["Caddyfile"] = caddy
	files["ocliv-relay.service"] = edgesystemd.RelayUnit()
	var dns strings.Builder
	if cfg.edge == "single-host" {
		fmt.Fprintf(&dns, "%s      A     <relay IPv4>\n", host)
		fmt.Fprintf(&dns, "%s      AAAA  <relay IPv6, if any>\n", host)
	} else if cfg.edge == "tunnel" {
		fmt.Fprintf(&dns, "%s      A     <relay IPv4>\n", host)
		fmt.Fprintf(&dns, "%s      AAAA  <relay IPv6, if any>\n", host)
		fmt.Fprintf(&dns, "*.t.%s        A     <relay IPv4>\n", cfg.domain)
		fmt.Fprintf(&dns, "On-demand TLS: no DNS-01 plugin needed — each *.t.%s tunnel hostname gets its own ACME certificate on first use via HTTP-01/TLS-ALPN-01, gated by the relay ask endpoint. Every used tunnel hostname must resolve here: prefer a *.t.%s wildcard A record; without provider wildcard support, add one A record per tunnel hostname (verify each with dig). ACME rate limits apply (~50 certificates/week/domain).\n", cfg.domain, cfg.domain)
	} else {
		fmt.Fprintf(&dns, "relay.%s      A     <relay IPv4>\n", cfg.domain)
		fmt.Fprintf(&dns, "*.t.%s        A     <relay IPv4>\n", cfg.domain)
		fmt.Fprintf(&dns, "ACME DNS-01: build Caddy with the %s plugin (stock Caddy ships none), then export %s=<provider credential> in Caddy's environment (never commit it) and scope it to this zone only.\n", cfg.dnsProvider, cfg.dnsEnv)
	}
	files["dns-records.txt"] = dns.String()
	return files
}

// checkInitDir verifies a generated deployment directory without
// activating anything: every expected file is present, the Caddyfile
// carries no unsubstituted placeholders and preserves the trusted-edge
// contract, relay.env names a valid domain (plus valid host overrides),
// and the unit keeps its hardening pins. It returns the failure lines;
// empty means the directory is internally consistent. Live reachability
// (DNS, ACME, relay serving) is not claimed here — see relay doctor.
func checkInitDir(outDir string) []string {
	var bad []string
	fail := func(format string, args ...any) {
		bad = append(bad, fmt.Sprintf(format, args...))
	}
	for _, name := range initFileTargets {
		if fi, err := os.Stat(filepath.Join(outDir, name)); err != nil || fi.IsDir() {
			fail("%s: missing", name)
		}
	}
	if len(bad) > 0 {
		return bad
	}
	envRaw, err := os.ReadFile(filepath.Join(outDir, "relay.env"))
	if err != nil {
		return []string{"relay.env: unreadable"}
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(envRaw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			env[k] = strings.TrimSpace(v)
		}
	}
	domain, derr := parseRelayDomain(env["OCLIV_DOMAIN"])
	if derr != nil {
		fail("relay.env: %v", derr)
	}
	for _, key := range []string{"OCLIV_MCP_HOST", "OCLIV_RELAY_HOST"} {
		if env[key] != "" {
			if _, herr := parseMCPHost(env[key]); herr != nil {
				fail("relay.env: %v", herr)
			}
		}
	}
	caddy, err := os.ReadFile(filepath.Join(outDir, "Caddyfile"))
	if err != nil {
		return append(bad, "Caddyfile: unreadable")
	}
	if strings.Contains(string(caddy), "{$") {
		fail("Caddyfile: unsubstituted placeholder remains")
	}
	// The edge must terminate TLS in front of the loopback relay and
	// preserve the header contract the relay trusts: overwrite
	// X-Forwarded-For/Proto, strip any smuggled X-Forwarded-Host.
	for _, want := range []string{
		"reverse_proxy 127.0.0.1:8080",
		"header_up X-Forwarded-For",
		"header_up X-Forwarded-Proto",
		"header_up -X-Forwarded-Host",
	} {
		if !strings.Contains(string(caddy), want) {
			fail("Caddyfile: missing %q", want)
		}
	}
	host := env["OCLIV_MCP_HOST"]
	if host == "" {
		host = "relay." + domain
	}
	if !strings.Contains(string(caddy), host) {
		fail("Caddyfile: does not serve %q", host)
	}
	if !strings.Contains(string(caddy), "tls ") || strings.Contains(string(caddy), "tls {$") {
		fail("Caddyfile: no concrete tls directive (ACME email unresolved)")
	}
	// A wildcard edge without an ACTIVE dns line cannot issue its
	// certificate: the issuance path must never be a commented
	// placeholder that passes generation but dies at runtime. The
	// tunnel edge instead issues per-hostname via on-demand, gated by
	// the relay ask endpoint — its own structural requirement.
	hasOnDemand := strings.Contains(string(caddy), "on_demand")
	for _, line := range strings.Split(string(caddy), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "dns ") && !strings.HasPrefix(t, "#") {
			goto dnsOK
		}
	}
	// Only the wildcard edge needs DNS-01; the single-host edge uses
	// plain ACME and the tunnel edge uses ask-gated on-demand, so
	// neither carries a dns line by design.
	if strings.Contains(string(caddy), "*.t.") && !hasOnDemand {
		fail("Caddyfile: wildcard edge has no active DNS-01 stanza (dns <provider> commented or missing)")
	}
	if hasOnDemand && !strings.Contains(string(caddy), "ask http://127.0.0.1:8080/v1/internal/ask") {
		fail("Caddyfile: on-demand issuance without the relay ask guard would dispense certificates for any domain pointed here")
	}
dnsOK:
	if strings.Contains(string(caddy), "<provider>") {
		fail("Caddyfile: unresolved <provider> placeholder remains")
	}
	// Staging markers must never ship in generated production files:
	// internal CA, tailnet/lab bind hints, or funnel overrides would
	// silently downgrade a public deployment to lab trust.
	for _, marker := range []string{"tls internal", "STAGING_", "100.113.85.107", ":10000"} {
		if strings.Contains(string(caddy), marker) {
			fail("Caddyfile: staging marker %q must not appear in generated production files", marker)
		}
	}
	unit, err := os.ReadFile(filepath.Join(outDir, "ocliv-relay.service"))
	if err != nil {
		return append(bad, "ocliv-relay.service: unreadable")
	}
	for _, want := range []string{
		"EnvironmentFile=/etc/ocliv/relay.env",
		"ExecStart=",
		"User=ocliv",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(string(unit), want) {
			fail("ocliv-relay.service: missing %q", want)
		}
	}
	dns, err := os.ReadFile(filepath.Join(outDir, "dns-records.txt"))
	if err != nil {
		return append(bad, "dns-records.txt: unreadable")
	}
	if !strings.Contains(string(dns), domain) && !strings.Contains(string(dns), host) {
		fail("dns-records.txt: names neither %q nor %q", domain, host)
	}
	return bad
}

// runRelayInitFiles validates, renders, and writes the deployment
// directory. It is split from cmdRelayInit for testability.
func runRelayInitFiles(cfg initConfig) error {
	if fi, err := os.Lstat(cfg.outDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to generate into symlinked --out %s", cfg.outDir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("--out %s exists and is not a directory", cfg.outDir)
		}
	}
	if err := os.MkdirAll(cfg.outDir, 0o700); err != nil {
		return err
	}
	files := buildInitFiles(cfg)
	for _, name := range initFileTargets {
		if err := writeInitFile(filepath.Join(cfg.outDir, name), files[name], 0o600); err != nil {
			return err
		}
	}
	// The service unit carries no secrets; relax to 0644 for systemd.
	unit := filepath.Join(cfg.outDir, "ocliv-relay.service")
	if err := os.Chmod(unit, 0o644); err != nil {
		return err
	}
	return nil
}
