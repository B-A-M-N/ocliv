// Relay administration: serve, init, doctor, enrollment issuance.
package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
		fmt.Fprintln(os.Stderr, "usage: ocliv relay init|serve|doctor|issue-enroll ...")
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
	default:
		fmt.Fprintf(os.Stderr, "unknown relay command %q\n", argv[0])
		return apperr.ExitCLIValidation
	}
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
		return addr, nil
	}
	if strings.EqualFold(host, "localhost") {
		return addr, nil
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
	return addr, nil
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
	if value == "example.com" || value == "example.net" || value == "example.org" {
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
		_ = srv.Serve(ln)
	}()
	return srv, nil
}

// cmdRelayServe runs the relay in the foreground (systemd runs this).
func cmdRelayServe(argv []string) int {
	addr, dataDir, rawDomain := relayFlags(argv)
	if _, err := parseRelayListen(addr, "listen"); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
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
		MCPExternalHost: mcpHost,
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
		fmt.Printf("mcp path-route ingress on https://%s/r/<route-id>/mcp\n", mcpHost)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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

// cmdRelayInit bootstraps relay config, secrets, and prints DNS records.
func cmdRelayInit(argv []string) int {
	_, dataDir, domain := relayFlags(argv)
	if domain == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv relay init --domain example.com [--data DIR]")
		return apperr.ExitCLIValidation
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	fmt.Println("Ocliv relay bootstrap for domain " + domain)
	fmt.Println("Data dir: " + dataDir)
	fmt.Println("NOTE: preparation-only — this command prints manual setup steps;")
	fmt.Println("it does not provision Caddy, systemd, certificates, or DNS.")
	fmt.Println()
	fmt.Println("Create these DNS records once:")
	fmt.Printf("  relay.%s      A     <VPS IPv4>\n", domain)
	fmt.Printf("  *.t.%s        A     <VPS IPv4>\n", domain)
	fmt.Println()
	fmt.Println("Then point Caddy at 127.0.0.1:8080; the edge must terminate TLS and strip inbound X-Forwarded-* headers (see docs/OPERATOR.md).")
	fmt.Println("Run `ocliv relay serve --domain " + domain + " --data " + dataDir + " [--mcp-host HOST] [--relay-host HOST]` under systemd.")
	fmt.Println("Run `ocliv relay issue-enroll --data " + dataDir + "` to mint an enrollment code.")
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
	res := doctor.CheckRelay(doctor.RelayInput{DataDir: dataDir, Domain: domain, CACertPath: cacert})
	fmt.Print(res.Report(false))
	if res.OK {
		return apperr.ExitOK
	}
	return apperr.ExitRelayTLS
}

// cmdIssueEnroll mints a one-time enrollment code (operator only).
func cmdIssueEnroll(argv []string) int {
	_, dataDir, _ := relayFlags(argv)
	var tenant string
	for _, a := range argv {
		if strings.HasPrefix(a, "--tenant=") {
			tenant = strings.TrimPrefix(a, "--tenant=")
		}
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
	code, err := relay.IssueEnrollmentCode(db, tenant, 24*time.Hour, "operator")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	fmt.Println("One-time enrollment code (valid 24h, show once):")
	fmt.Println(code)
	return apperr.ExitOK
}

// cmdAccess wraps share/rotate/revoke for the current lease.
