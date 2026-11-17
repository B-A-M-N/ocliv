// Relay administration: serve, init, doctor, enrollment issuance.
package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/doctor"
	"ocliv/internal/limits"
	"ocliv/internal/relay"
	"ocliv/internal/server"
	"ocliv/internal/store"
)

// restrictFileCreation limits files created by the relay process to
// owner-only by default (P1-3): SQLite sidecars (-wal/-shm) created
// mid-run must not inherit a permissive umask. store.Open chmods what
// exists at open; this covers what the running relay creates later.
func restrictFileCreation() {
	syscall.Umask(0o077)
}

// cmdRelay handles relay-side operations.
func cmdRelay(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay init|serve|doctor|issue-enroll|enroll-ssh|keys|revoke-key|tenants|backup|validate-backup|restore ...")
		return apperr.ExitCLIValidation
	}
	switch argv[0] {
	case "serve":
		return cmdRelayServe(argv[1:])
	case "init":
		return cmdRelayInit(argv[1:])
	case "doctor":
		return cmdRelayDoctor(argv[1:])
	case "issue-enroll":
		return cmdIssueEnroll(argv[1:])
	case "enroll-ssh":
		return cmdRelayEnrollSSH(argv[1:])
	case "keys":
		return cmdRelayKeys(argv[1:])
	case "revoke-key":
		return cmdRelayRevokeKey(argv[1:])
	case "tenants":
		return cmdRelayTenants(argv[1:])
	case "backup":
		return cmdRelayBackup(argv[1:])
	case "validate-backup":
		return cmdRelayValidateBackup(argv[1:])
	case "restore":
		return cmdRelayRestore(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown relay command %q\n", argv[0])
		return apperr.ExitCLIValidation
	}
}

// cmdRelayValidateBackup verifies a backup checksum sidecar, SQLite integrity,
// and supported schema without opening or changing the live relay database.
func cmdRelayValidateBackup(argv []string) int {
	in := ""
	for i := 0; i < len(argv); i++ {
		if v, ok := mcpFlagValue(argv, &i, "in"); ok {
			in = v
		} else {
			fmt.Fprintln(os.Stderr, "usage: ocliv relay validate-backup --in FILE")
			return apperr.ExitCLIValidation
		}
	}
	if in == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay validate-backup --in FILE")
		return apperr.ExitCLIValidation
	}
	if err := relay.ValidateBackup(in); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}
	fmt.Printf("backup validated: %s\n", in)
	return apperr.ExitOK
}

// relayFlags parses shared relay flags.
// parseRelayListen validates a relay ingress listener. Production relay
// ingress must stay behind the TLS edge, so only loopback listeners are
// accepted; wildcard, unspecified, and public addresses are rejected
// outright (P0-07). There is no override: remote exposure must go
// through the edge, never around it.
func parseRelayListen(addr, flag string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "", fmt.Errorf("invalid --"+flag+" %q: want host:port", addr)
	}
	if host == "" {
		return "", fmt.Errorf("invalid --"+flag+" %q: wildcard listeners would bypass the TLS edge; use 127.0.0.1", addr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return "", fmt.Errorf("invalid --"+flag+" %q: non-loopback listeners would bypass the TLS edge", addr)
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("invalid --"+flag+" %q: cannot verify loopback", addr)
	}
	for _, ip := range addrs {
		if !ip.IsLoopback() {
			return "", fmt.Errorf("invalid --"+flag+" %q: resolves outside loopback", addr)
		}
	}
	// Bind the resolved numeric literal, not the hostname: re-resolving
	// at Listen time would let a DNS change bypass this check (TOCTOU).
	return net.JoinHostPort(addrs[0].String(), port), nil
}

// parseHostname validates an exact dotted hostname used for relay
// addressing. There is no safe default: serving under a placeholder or
// an empty/invalid hostname would mint state in the wrong namespace,
// so startup refuses instead of guessing (A05, A06, D01, H02).
func parseHostname(value, flag string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", fmt.Errorf("relay %s is required (e.g. %s example.org)", flag, flag)
	}
	if value == "example.com" || value == "example.net" || value == "example.org" ||
		strings.HasSuffix(value, ".example.com") || strings.HasSuffix(value, ".example.net") ||
		strings.HasSuffix(value, ".example.org") {
		return "", fmt.Errorf("relay %s %q is a placeholder; configure the real domain", flag, value)
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("relay %s %q must be a dotted hostname", flag, value)
	}
	for _, lb := range labels {
		if len(lb) == 0 || len(lb) > 63 {
			return "", fmt.Errorf("relay %s %q has a bad label", flag, value)
		}
		for _, c := range lb {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("relay %s %q has invalid characters", flag, value)
			}
		}
		if lb[0] == '-' || lb[len(lb)-1] == '-' {
			return "", fmt.Errorf("relay %s %q has a bad label", flag, value)
		}
	}
	return value, nil
}

// parseRelayDomain validates the production relay domain.
func parseRelayDomain(domain string) (string, error) {
	return parseHostname(domain, "--domain")
}

// parseMCPHost validates the exact public hostname serving single-host
// MCP routes (/r/<route-id>/mcp). Empty is never valid here: the caller
// only invokes this when --mcp-host was explicitly passed, and an absent
// flag disables path-route ingress entirely (P0-A).
func parseMCPHost(host string) (string, error) {
	return parseHostname(host, "--mcp-host")
}

func relayFlags(argv []string) (addr, dataDir, domain string) {
	addr = "127.0.0.1:8080"
	dataDir = "./ocliv-relay-data"
	for i := 0; i < len(argv); i++ {
		switch {
		case strings.HasPrefix(argv[i], "--listen="):
			addr = strings.TrimPrefix(argv[i], "--listen=")
		case argv[i] == "--listen" && i+1 < len(argv):
			i++
			addr = argv[i]
		case argv[i] == "--data" && i+1 < len(argv):
			i++
			dataDir = argv[i]
		case strings.HasPrefix(argv[i], "--data="):
			dataDir = strings.TrimPrefix(argv[i], "--data=")
		case strings.HasPrefix(argv[i], "--domain="):
			domain = strings.TrimPrefix(argv[i], "--domain=")
		case argv[i] == "--domain" && i+1 < len(argv):
			i++
			domain = argv[i]
		}
	}
	return addr, dataDir, domain
}

// mcpHostFlag scans relay argv for an explicitly passed --mcp-host,
// accepting space and `=` forms per house style. Last wins. Absent
// means single-host MCP ingress stays disabled (P0-A).
func mcpHostFlag(argv []string) (raw string, seen bool) {
	return explicitRelayFlag(argv, "--mcp-host")
}

// mcpPortFlag scans relay argv for an explicitly passed --mcp-port,
// accepting space and `=` forms per house style. Last wins.
func mcpPortFlag(argv []string) (raw string, seen bool) {
	return explicitRelayFlag(argv, "--mcp-port")
}

// parseMCPPort validates the public edge port minted into route URLs:
// 1-65535, with 443 the ordinary public value. Anything else fails
// closed rather than minting an unreachable URL.
func parseMCPPort(raw string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("relay --mcp-port %q must be 1-65535", raw)
	}
	return p, nil
}

// healthListenFlag scans relay argv for an explicitly passed
// --health-listen, accepting space and `=` forms per house style. Last
// wins. Absent means the default loopback listener below.
func healthListenFlag(argv []string) (raw string, seen bool) {
	return explicitRelayFlag(argv, "--health-listen")
}

// relayHostFlag scans relay argv for an explicitly passed --relay-host,
// accepting space and `=` forms per house style. Last wins. Absent means
// the control authority stays relay.<domain>; passed for public hostnames
// that are not named relay.<domain> (e.g. temporary *.ts.net ingress).
func relayHostFlag(argv []string) (raw string, seen bool) {
	return explicitRelayFlag(argv, "--relay-host")
}

// explicitRelayFlag scans argv for one --name= / --name value flag.
// Last wins; a bare trailing --name counts as seen with an empty value.
func explicitRelayFlag(argv []string, name string) (raw string, seen bool) {
	for i := 0; i < len(argv); i++ {
		switch {
		case strings.HasPrefix(argv[i], name+"="):
			raw, seen = strings.TrimPrefix(argv[i], name+"="), true
		case argv[i] == name && i+1 < len(argv):
			i++
			raw, seen = argv[i], true
		case argv[i] == name:
			raw, seen = "", true
		}
	}
	return raw, seen
}

// startHealthListener binds the internal health/metrics listener,
// reporting bind failures loudly instead of dropping them. The caller
// owns shutdown via srv.Shutdown.
func startHealthListener(addr string, h http.Handler) (*http.Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("health listener on %s: %w", addr, err)
	}
	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		// Abnormal listener death must be visible in the journal;
		// graceful Shutdown reports ErrServerClosed and stays quiet.
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "health listener error: "+err.Error())
		}
	}()
	return srv, nil
}

// parseAutoApproveRedirectHosts parses and validates a comma-separated list
// of exact hostnames/IPs for --auto-approve-redirect-hosts. Wildcards,
// schemes, paths, and ports are rejected so typos fail closed at startup.
func parseAutoApproveRedirectHosts(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		h := strings.ToLower(strings.TrimSpace(part))
		if h == "" {
			return nil, fmt.Errorf("--auto-approve-redirect-hosts contains an empty entry")
		}
		if strings.Contains(h, "*") || strings.Contains(h, "://") || strings.Contains(h, "/") || strings.Contains(h, ":") {
			return nil, fmt.Errorf("--auto-approve-redirect-hosts entry %q must be an exact hostname or IP literal (no wildcards, scheme, port, or path)", part)
		}
		if h != "localhost" && net.ParseIP(h) == nil {
			norm, err := parseHostname(h, "--auto-approve-redirect-hosts")
			if err != nil {
				return nil, err
			}
			h = norm
		}
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out, nil
}

// cmdRelayServe runs the relay in the foreground (systemd runs this).
func cmdRelayServe(argv []string) int {
	addr, dataDir, rawDomain := relayFlags(argv)
	bindAddr, err := parseRelayListen(addr, "listen")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	// Bind the validated numeric literal, never re-resolve the raw
	// hostname at ListenAndServe time.
	addr = bindAddr
	domain, err := parseRelayDomain(rawDomain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	// The control authority defaults to relay.<domain>. An explicit
	// --relay-host overrides it for public hostnames that are not named
	// relay.<domain> (e.g. temporary *.ts.net ingress): agent control
	// still requires the exact configured authority, unchanged.
	relayHost := "relay." + domain
	if rawRelayHost, seen := relayHostFlag(argv); seen {
		h, err := parseHostname(rawRelayHost, "--relay-host")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		relayHost = h
	}
	// Single-host MCP ingress is explicit opt-in: without --mcp-host the
	// relay serves only wildcard tunnel hosts and control endpoints, and
	// mcp-route creation fails closed (P0-A).
	mcpHost := ""
	if rawMCPHost, seen := mcpHostFlag(argv); seen {
		h, err := parseMCPHost(rawMCPHost)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		mcpHost = h
	}
	// --mcp-port carries a non-443 public edge port (lab Caddy on 8444)
	// into minted route URLs. It never affects Host admission, which
	// strips ports (canonicalHost). Without --mcp-host it is rejected:
	// a port with no path-route ingress is a misconfiguration, not a default.
	mcpPort := 0
	if rawMCPPort, seen := mcpPortFlag(argv); seen {
		p, err := parseMCPPort(rawMCPPort)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		if mcpHost == "" {
			fmt.Fprintln(os.Stderr, "error: --mcp-port needs --mcp-host")
			return apperr.ExitCLIValidation
		}
		mcpPort = p
	}
	rawAutoApprove := os.Getenv("OCLIV_AUTO_APPROVE_REDIRECT_HOSTS")
	if v, seen := explicitRelayFlag(argv, "--auto-approve-redirect-hosts"); seen {
		rawAutoApprove = v
	}
	autoApproveHosts, err := parseAutoApproveRedirectHosts(rawAutoApprove)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	restrictFileCreation()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	srv, err := relay.New(relay.Options{
		DB: db, Namespace: "t." + domain, RelayHost: relayHost,
		MCPExternalHost: mcpHost, MCPExternalPort: mcpPort,
		AutoApproveRedirectHosts: autoApproveHosts,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	// Readiness is the relay's own prerequisites — writable state,
	// initialized routing, available capacity — not public DNS/TLS or
	// route liveness, which stay external doctor checks (P2-2).
	health := &server.Health{Ready: func() bool {
		return srv.ReadyForSessions()
	}}
	// The health/metrics listener binds explicitly on loopback only
	// (P2): operator-configurable for multi-instance hosts, but never
	// publicly reachable. A bind failure is reported loudly instead of
	// silently dropped, and the listener shuts down with the relay.
	healthAddr := "127.0.0.1:18080"
	if rawHealth, seen := healthListenFlag(argv); seen {
		h, err := parseRelayListen(rawHealth, "health-listen")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		healthAddr = h
	}
	healthSrv, err := startHealthListener(healthAddr, health.Handler())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	fmt.Fprintf(os.Stderr, "health listener on %s\n", healthSrv.Addr)
	fmt.Printf("ocliv relay serving behind TLS edge on %s (namespace t.%s)\n", addr, domain)
	if mcpHost != "" {
		base := "https://" + mcpHost
		if mcpPort != 0 && mcpPort != 443 {
			base += ":" + strconv.Itoa(mcpPort)
		}
		fmt.Printf("mcp path-route ingress on %s/r/<route-id>/mcp\n", base)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Authorization-state maintenance rides the relay's own lifecycle:
	// expired codes/challenges, retention-expired revocations, and
	// abandoned client registrations are reclaimed while the relay runs,
	// not only at startup. No second service is created; the loop ends
	// with the relay.
	go srv.RunAuthzMaintenance(ctx)
	// G06: bound slow-trickle connections. ReadTimeout caps total request
	// ingress (the 64MiB body cap keeps this generous for legit uploads);
	// IdleTimeout reaps dead keep-alive connections. WriteTimeout stays
	// unset: SSE visitor streams never terminate, so a total write
	// deadline would kill every long-lived stream. Slow readers on finite
	// bodies remain a residual risk (see final report).
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    limits.MaxHeaderBytes, // G01: wire the header cap
	}
	go func() {
		<-ctx.Done()
		_ = httpSrv.Shutdown(context.Background())
		_ = healthSrv.Shutdown(context.Background())
	}()
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "relay error: "+err.Error())
		return apperr.ExitInternal
	}
	return apperr.ExitCleanShutdown
}

// cmdRelayInit validates its inputs and generates a reviewable deployment
// directory (relay.env, Caddyfile, systemd unit, DNS records). It never
// touches live system paths and never activates anything: preparation-only
// generation, with manual setup steps printed for the operator.
func cmdRelayInit(argv []string) int {
	cfg, code := parseRelayInit(argv)
	if code != 0 {
		return code
	}
	if cfg.checkOnly {
		if bad := checkInitDir(cfg.outDir); len(bad) > 0 {
			for _, line := range bad {
				fmt.Fprintln(os.Stderr, "init check: "+line)
			}
			return apperr.ExitInternal
		}
		fmt.Println("init check: deployment dir consistent (files, placeholders, edge contract, env, unit)")
		fmt.Println("NOTE: internal consistency only — DNS, ACME, and live relay serving are not proven here; see `ocliv relay doctor`.")
		return apperr.ExitOK
	}
	if err := runRelayInitFiles(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	fmt.Println("Ocliv relay bootstrap for domain " + cfg.domain)
	fmt.Println("Data dir: " + cfg.dataDir)
	fmt.Println("Deployment dir: " + cfg.outDir + " (relay.env, Caddyfile, ocliv-relay.service, dns-records.txt)")
	fmt.Println("NOTE: preparation-only — this command generates files and prints manual setup steps;")
	fmt.Println("it does not provision Caddy, systemd, certificates, or DNS.")
	fmt.Println()
	fmt.Println("Create these DNS records once (see dns-records.txt):")
	if cfg.edge == "single-host" {
		fmt.Printf("  %s      A     <relay IPv4>\n", cfg.mcpHost)
	} else {
		fmt.Printf("  relay.%s      A     <VPS IPv4>\n", cfg.domain)
		fmt.Printf("  *.t.%s        A     <VPS IPv4>\n", cfg.domain)
	}
	fmt.Println()
	fmt.Println("Review the deployment dir, copy relay.env to /etc/ocliv/relay.env (root-owned, 0600),")
	fmt.Println("install the Caddyfile and unit, then start the relay under systemd (see docs/OPERATOR.md).")
	fmt.Println("Run `ocliv relay issue-enroll --data " + cfg.dataDir + "` to mint an enrollment code.")
	return apperr.ExitOK
}

// cmdRelayDoctor checks relay-side prerequisites.

func cmdRelayDoctor(argv []string) int {
	_, dataDir, rawDomain := relayFlags(argv)
	domain, err := parseRelayDomain(rawDomain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	// Honor an explicit --relay-host (Round 18): the relay doctor must
	// probe the configured control authority, not a relay.<domain>
	// guess that does not exist on --relay-host deployments.
	relayHost := ""
	if rawRelayHost, seen := relayHostFlag(argv); seen {
		h, herr := parseHostname(rawRelayHost, "--relay-host")
		if herr != nil {
			fmt.Fprintln(os.Stderr, "error: "+herr.Error())
			return apperr.ExitCLIValidation
		}
		relayHost = h
	}
	var cacert string
	for i := 0; i < len(argv); i++ {
		if strings.HasPrefix(argv[i], "--cacert=") {
			cacert = strings.TrimPrefix(argv[i], "--cacert=")
		} else if argv[i] == "--cacert" && i+1 < len(argv) {
			i++
			cacert = argv[i]
		}
	}
	if cacert == "" {
		cacert = os.Getenv("OCLIV_CACERT")
	}
	res := doctor.CheckRelay(doctor.RelayInput{DataDir: dataDir, Domain: domain, RelayHost: relayHost, CACertPath: cacert})
	fmt.Print(res.Report())
	if res.OK {
		return apperr.ExitOK
	}
	return apperr.ExitRelayTLS
}

// cmdIssueEnroll mints a one-time enrollment code (operator only).
//
// The tenant argument is a SCOPE decision: an explicit --tenant must be
// honored exactly, because a publisher enrolled in the wrong tenant lands
// in the wrong administrative scope. Both spellings are accepted (--tenant
// NAME and --tenant=NAME); an explicit but empty or missing value is
// REFUSED (exit 2, no code minted) instead of being ignored. Only the
// complete absence of --tenant means "mint a fresh enrollment in a new
// tenant namespace".
func cmdIssueEnroll(argv []string) int {
	_, dataDir, _ := relayFlags(argv)
	var tenant string
	tenantSet := false
	ttl := 24 * time.Hour
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--help" || a == "-h" {
			fmt.Fprintln(os.Stderr, "usage: ocliv relay issue-enroll [--data DIR] [--tenant NAME] [--ttl DURATION]")
			return apperr.ExitCLIValidation
		}
		if a == "--tenant" {
			// Space form: the value is the NEXT argument. A missing
			// value is a refusal, never a silently invented scope. A
			// following flag is not a value either: consuming it would
			// bind the enrollment to the literal string "--data".
			if i+1 >= len(argv) || strings.HasPrefix(argv[i+1], "--") {
				fmt.Fprintln(os.Stderr, "issue-enroll: --tenant needs a value")
				return apperr.ExitCLIValidation
			}
			i++
			tenant = argv[i]
			tenantSet = true
			continue
		}
		if strings.HasPrefix(a, "--tenant=") {
			tenant = strings.TrimPrefix(a, "--tenant=")
			tenantSet = true
			continue
		}
		if a == "--ttl" || strings.HasPrefix(a, "--ttl=") {
			v, ok := mcpFlagValue(argv, &i, "ttl")
			if !ok {
				return apperr.ExitCLIValidation
			}
			d, derr := time.ParseDuration(v)
			if derr != nil || d <= 0 || d > 168*time.Hour {
				fmt.Fprintf(os.Stderr, "issue-enroll: invalid --ttl %q (want 1s..168h)\n", v)
				return apperr.ExitCLIValidation
			}
			ttl = d
		}
	}
	if tenantSet && strings.TrimSpace(tenant) == "" {
		fmt.Fprintln(os.Stderr, "issue-enroll: --tenant needs a non-empty value")
		return apperr.ExitCLIValidation
	}
	restrictFileCreation()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	// Narrow operator operation only: never construct a relay Server here,
	// its boot reconciliation would disturb live leases (P0-01).
	code, err := relay.IssueEnrollmentCode(db, tenant, ttl, "operator")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	fmt.Println("One-time enrollment code (valid 24h, show once):")
	fmt.Println(code)
	return apperr.ExitOK
}

// openRelayDB opens the relay database for operator-local commands.
// Like issue-enroll, these never construct a Server (P0-01): they commit
// durable state and the running relay converges via admission and its
// supervise revalidation, so no restart is required.
func openRelayDB(argv []string) (*store.DB, int) {
	_, dataDir, _ := relayFlags(argv)
	restrictFileCreation()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return nil, apperr.ExitInternal
	}
	return db, apperr.ExitOK
}

// exitForRelayErr maps a relay operation failure to a CLI exit status.
func exitForRelayErr(err error) int {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return apperr.ExitFor(ae.Code)
	}
	return apperr.ExitInternal
}

// cmdRelayKeys implements `ocliv relay keys list`.
func cmdRelayKeys(argv []string) int {
	if len(argv) == 0 || argv[0] != "list" {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay keys list [--data DIR]")
		return apperr.ExitCLIValidation
	}
	_, dataDir, _ := relayFlags(argv[1:])
	db, err := openRelayDBReadOnly(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	keys, err := relay.ListAgentKeysReadOnly(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}
	if len(keys) == 0 {
		fmt.Println("no enrolled agent keys")
		return apperr.ExitOK
	}
	fmt.Printf("%-24s %-20s %-10s %s\n", "KEY ID", "TENANT", "STATUS", "ENROLLED")
	for _, k := range keys {
		fmt.Printf("%-24s %-20s %-10s %s\n", k.ID, k.TenantID, k.Status, k.CreatedAt)
	}
	return apperr.ExitOK
}

// cmdRelayRevokeKey implements `ocliv relay revoke-key --key-id ID`.
func cmdRelayRevokeKey(argv []string) int {
	var keyID, reason string
	for i := 0; i < len(argv); i++ {
		if v, ok := mcpFlagValue(argv, &i, "key-id"); ok {
			keyID = v
		} else if v, ok := mcpFlagValue(argv, &i, "reason"); ok {
			reason = v
		} else if argv[i] == "--data" && i+1 < len(argv) {
			i++
		} else if strings.HasPrefix(argv[i], "--data=") {
			continue
		} else {
			fmt.Fprintln(os.Stderr, "usage: ocliv relay revoke-key --key-id ID [--reason TEXT] [--data DIR]")
			return apperr.ExitCLIValidation
		}
	}
	if keyID == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay revoke-key --key-id ID [--reason TEXT] [--data DIR]")
		return apperr.ExitCLIValidation
	}
	db, code := openRelayDB(argv)
	if code != 0 {
		return code
	}
	defer db.Close()
	affected, err := relay.RevokeAgentKeyDB(db, keyID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}
	if reason == "" {
		reason = "operator revoke-key"
	}
	db.Audit("operator", "", keyID, "agent_key_revoke", "ok", reason)
	fmt.Printf("revoked key %s (%d leases terminally revoked)\n", keyID, len(affected))
	fmt.Println("a running relay terminates forwarding within its supervise interval; no restart required")
	return apperr.ExitOK
}

// cmdRelayTenants implements `ocliv relay tenants suspend|unsuspend`.
func cmdRelayTenants(argv []string) int {
	if len(argv) == 0 || (argv[0] != "suspend" && argv[0] != "unsuspend") {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay tenants suspend|unsuspend --tenant ID [--reason TEXT] [--data DIR]")
		return apperr.ExitCLIValidation
	}
	op := argv[0]
	var tenant, reason string
	for i := 1; i < len(argv); i++ {
		if v, ok := mcpFlagValue(argv, &i, "tenant"); ok {
			tenant = v
		} else if v, ok := mcpFlagValue(argv, &i, "reason"); ok {
			reason = v
		} else if argv[i] == "--data" && i+1 < len(argv) {
			i++
		} else if strings.HasPrefix(argv[i], "--data=") {
			continue
		} else {
			fmt.Fprintln(os.Stderr, "usage: ocliv relay tenants suspend|unsuspend --tenant ID [--reason TEXT] [--data DIR]")
			return apperr.ExitCLIValidation
		}
	}
	if tenant == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay tenants suspend|unsuspend --tenant ID [--reason TEXT] [--data DIR]")
		return apperr.ExitCLIValidation
	}
	db, code := openRelayDB(argv)
	if code != 0 {
		return code
	}
	defer db.Close()
	if reason == "" {
		reason = "operator tenants " + op
	}
	if op == "suspend" {
		affected, err := relay.SuspendTenantDB(db, tenant)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return exitForRelayErr(err)
		}
		db.Audit("operator", tenant, "", "tenant_suspend", "ok", reason)
		fmt.Printf("suspended tenant %s (%d leases terminally revoked; keys stay revoked on unsuspend)\n", tenant, len(affected))
		return apperr.ExitOK
	}
	if err := relay.UnsuspendTenantDB(db, tenant); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}
	db.Audit("operator", tenant, "", "tenant_unsuspend", "ok", reason)
	fmt.Printf("unsuspended tenant %s (re-enroll publishers explicitly; old keys stay revoked)\n", tenant)
	return apperr.ExitOK
}

// cmdRelayBackup implements `ocliv relay backup --data DIR --out FILE`.
// The snapshot is a consistent VACUUM INTO image with owner-only
// permissions; validating it (integrity + schema) is part of restore,
// not backup, so backup stays usable while the relay runs.
func cmdRelayBackup(argv []string) int {
	out := ""
	for i := 0; i < len(argv); i++ {
		if v, ok := mcpFlagValue(argv, &i, "out"); ok {
			out = v
		} else if argv[i] == "--data" && i+1 < len(argv) {
			i++
		} else if strings.HasPrefix(argv[i], "--data=") {
			continue
		} else {
			fmt.Fprintln(os.Stderr, "usage: ocliv relay backup --data DIR --out FILE")
			return apperr.ExitCLIValidation
		}
	}
	if out == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay backup --data DIR --out FILE")
		return apperr.ExitCLIValidation
	}
	db, code := openRelayDB(argv)
	if code != 0 {
		return code
	}
	defer db.Close()
	if err := relay.BackupState(db, out); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}
	fmt.Printf("backup written: %s (stop the relay before restoring from it)\n", out)
	return apperr.ExitOK
}

// cmdRelayRestore implements
// `ocliv relay restore --data DIR --in FILE [--reset-authority] --relay-stopped`.
// The operator must stop the relay first and attest it; restore refuses
// revocation rollback unless --reset-authority explicitly distrusts
// everything restored (re-enrollment required afterwards).
func cmdRelayRestore(argv []string) int {
	in := ""
	reset := false
	stopped := false
	for i := 0; i < len(argv); i++ {
		if v, ok := mcpFlagValue(argv, &i, "in"); ok {
			in = v
		} else if argv[i] == "--reset-authority" {
			reset = true
		} else if argv[i] == "--relay-stopped" {
			stopped = true
		} else if argv[i] == "--data" && i+1 < len(argv) {
			i++
		} else if strings.HasPrefix(argv[i], "--data=") {
			continue
		} else {
			fmt.Fprintln(os.Stderr, "usage: ocliv relay restore --data DIR --in FILE [--reset-authority] --relay-stopped")
			return apperr.ExitCLIValidation
		}
	}
	if in == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay restore --data DIR --in FILE [--reset-authority] --relay-stopped")
		return apperr.ExitCLIValidation
	}
	_, dataDir, _ := relayFlags(argv)
	if err := relay.RestoreState(dataDir, in, reset, stopped); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}
	if reset {
		fmt.Println("restore complete with reset-authority: all keys, leases, publications, and managed OAuth clients/grants revoked, and the managed signing key retired; re-enroll publishers and re-register/re-approve managed clients, then start the relay")
	} else {
		fmt.Println("restore complete: start the relay (restored image takes effect at next start)")
	}
	return apperr.ExitOK
}

// cmdRelayEnrollSSH mints a one-time enrollment code on the relay host and
// pipes it over SSH stdin to `ocliv login --relay URL --code-file -` on the
// target node so the operator never has to copy/paste a code.
func cmdRelayEnrollSSH(argv []string) int {
	_, dataDir, _ := relayFlags(argv)
	var target, relayURL, tenant, profile string
	for i := 0; i < len(argv); i++ {
		switch {
		case argv[i] == "--help" || argv[i] == "-h":
			fmt.Fprintln(os.Stderr, "usage: ocliv relay enroll-ssh --target USER@HOST --relay URL [--data DIR] [--tenant NAME] [--profile NAME]")
			return apperr.ExitCLIValidation
		case argv[i] == "--target" || strings.HasPrefix(argv[i], "--target="):
			v, ok := mcpFlagValue(argv, &i, "target")
			if !ok {
				return apperr.ExitCLIValidation
			}
			target = v
		case argv[i] == "--relay" || strings.HasPrefix(argv[i], "--relay="):
			v, ok := mcpFlagValue(argv, &i, "relay")
			if !ok {
				return apperr.ExitCLIValidation
			}
			relayURL = v
		case argv[i] == "--tenant" || strings.HasPrefix(argv[i], "--tenant="):
			v, ok := mcpFlagValue(argv, &i, "tenant")
			if !ok {
				return apperr.ExitCLIValidation
			}
			tenant = v
		case argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		case argv[i] == "--data" || strings.HasPrefix(argv[i], "--data="):
			_, _ = mcpFlagValue(argv, &i, "data")
		default:
			fmt.Fprintf(os.Stderr, "enroll-ssh: unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if target == "" || relayURL == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay enroll-ssh --target USER@HOST --relay URL [--data DIR] [--tenant NAME] [--profile NAME]")
		return apperr.ExitCLIValidation
	}
	if strings.HasPrefix(target, "-") || strings.ContainsAny(target, " \t\r\n") {
		fmt.Fprintln(os.Stderr, "enroll-ssh: --target must be USER@HOST without leading '-' or whitespace")
		return apperr.ExitCLIValidation
	}
	if profile != "" && (strings.HasPrefix(profile, "-") || strings.ContainsAny(profile, " \t\r\n")) {
		fmt.Fprintln(os.Stderr, "enroll-ssh: invalid --profile")
		return apperr.ExitCLIValidation
	}
	restrictFileCreation()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	code, err := relay.IssueEnrollmentCode(db, tenant, 15*time.Minute, "operator")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}
	remoteArgs := []string{"--", target, "ocliv", "login", "--relay", relayURL, "--code-file", "-"}
	if profile != "" {
		remoteArgs = append(remoteArgs, "--profile", profile)
	}
	cmd := exec.Command("ssh", remoteArgs...)
	cmd.Stdin = strings.NewReader(code + "\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "enroll-ssh: remote login failed: %v\n", err)
		return apperr.ExitInternal
	}
	return apperr.ExitOK
}

// cmdAccess wraps share/rotate/revoke for the current lease.
