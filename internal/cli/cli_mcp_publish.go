package cli

// Focused MCP lifecycle orchestration: `mcp publish`, `mcp serve`, and
// `mcp doctor` (P1). One typed config selects the local MCP source and
// the authorization profile; the service then owns process and tunnel
// lifecycle without a daemon manager, shell, or second state authority.
//
//   - publish --local URL --auth A: tunnel to an already-listening
//     loopback MCP server in mode A, register the single-host route,
//     print the stable endpoint, run until Ctrl+C, then delete the route
//     and close the lease with independently recorded outcomes.
//   - publish --stdio is rejected: the stdio bridge cannot enforce MCP
//     authentication yet, so only --local (an already-listening loopback
//     MCP server) can be published. Run a child loopback-only via
//     `mcp expose` (never remotely reachable).
//   - serve: lifecycle only (tunnel, no route registration) — for
//     wildcard-namespace use or pre-publish verification.
//   - doctor: read-only diagnostics; never prints secrets.
//
// `mcp expose` and `mcp manage` are untouched. There is no --public
// flag: MCP leases are never public, and generic tunnels stay protected
// by default.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
)

// mcpAuthProfiles maps the operator-facing --auth values to the signed
// path segments the relay enforces (P0-B). The relay owns the binding;
// the CLI never invents profile names.
var mcpAuthProfiles = map[string]string{
	"upstream-oauth":    "upstream-oauth",
	"fixture-anonymous": "fixture-anonymous",
}

// mcpPublishConfig is the single typed publish/serve configuration
// parsed once from argv and handed to the lifecycle service.
type mcpPublishConfig struct {
	localURL string
	stdio    bool
	auth     string
	name     string
	ttl      string
	dir      string
	env      []string
	cmd      []string
	serve    bool // serve: lifecycle without route registration
	// strictDiscovery refuses to enter steady state when OAuth
	// resource discovery is unproven (P2-2). Default warns and
	// continues (availability); strict deletes the route and fails
	// closed so an unverified binding never serves.
	strictDiscovery bool
}

// abandonPublishedRoute deletes a registered route when publication
// aborts after registration. Route deletion and lease closure are
// independent outcomes: every abort-after-registration path attempts
// the DELETE (bad discovery URL, invalid binding, strict-unreachable)
// and reports its result, then closes the lease regardless — a closed
// lease denies forwarding, but the route row must not linger
// unverified (audit P1). Returns the relay status and trimmed detail.
func abandonPublishedRoute(del func(path string) (int, string), routeLeaseID, routeID string) (int, string) {
	status, body := del("/v1/agent/lease/" + routeLeaseID + "/mcp-route/" + routeID)
	return status, shortDetail(body)
}

// discoveryFailureFatal reports whether a discovery error must abort
// publication: invalid bindings always abort; unreachable discovery
// aborts only in strict mode, where an unproven binding must never
// serve. Default mode warns and continues (explicitly permitted).
func discoveryFailureFatal(cfg mcpPublishConfig, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errDiscoveryUnreachable) {
		return cfg.strictDiscovery
	}
	return true
}

// mcpFlagValue accepts both `--flag value` (house style for `ocliv PORT`
// and the target publish UX) and `--flag=value` (house style for the
// existing `mcp` subcommands). A missing value fails closed.
func mcpFlagValue(argv []string, i *int, name string) (string, bool) {
	a := argv[*i]
	if a == "--"+name {
		if *i+1 >= len(argv) {
			fmt.Fprintf(os.Stderr, "flag --%s needs a value\n", name)
			return "", false
		}
		*i++
		return argv[*i], true
	}
	if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
		return v, true
	}
	return "", false
}

func parseMCPPublish(argv []string, serve bool) (mcpPublishConfig, int) {
	var c mcpPublishConfig
	c.serve = serve
	var rest []string
	seenDashDash := false
	bad := func() (mcpPublishConfig, int) {
		fmt.Fprintln(os.Stderr, "usage: ocliv mcp publish --local URL --auth upstream-oauth|fixture-anonymous [--name N] [--ttl D] [--strict-discovery]")
		return c, apperr.ExitCLIValidation
	}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !seenDashDash && a == "--" {
			seenDashDash = true
			rest = argv[i+1:]
			break
		}
		if !seenDashDash && (a == "--local" || strings.HasPrefix(a, "--local=")) {
			v, ok := mcpFlagValue(argv, &i, "local")
			if !ok {
				return bad()
			}
			c.localURL = v
		} else if !seenDashDash && a == "--stdio" {
			c.stdio = true
		} else if !seenDashDash && (a == "--auth" || strings.HasPrefix(a, "--auth=")) {
			v, ok := mcpFlagValue(argv, &i, "auth")
			if !ok {
				return bad()
			}
			c.auth = v
		} else if !seenDashDash && (a == "--name" || strings.HasPrefix(a, "--name=")) {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				return bad()
			}
			c.name = v
		} else if !seenDashDash && (a == "--ttl" || strings.HasPrefix(a, "--ttl=")) {
			v, ok := mcpFlagValue(argv, &i, "ttl")
			if !ok {
				return bad()
			}
			c.ttl = v
		} else if !seenDashDash && a == "--strict-discovery" {
			c.strictDiscovery = true
		} else if !seenDashDash && (a == "--dir" || strings.HasPrefix(a, "--dir=")) {
			v, ok := mcpFlagValue(argv, &i, "dir")
			if !ok {
				return bad()
			}
			c.dir = v
		} else if !seenDashDash && (a == "--env" || strings.HasPrefix(a, "--env=")) {
			v, ok := mcpFlagValue(argv, &i, "env")
			if !ok {
				return bad()
			}
			c.env = append(c.env, v)
		} else if !seenDashDash && strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return bad()
		} else {
			rest = argv[i:]
			break
		}
	}
	c.cmd = rest
	if _, ok := mcpAuthProfiles[c.auth]; !ok {
		return bad()
	}
	if c.localURL == "" && !c.stdio {
		fmt.Fprintln(os.Stderr, "publish needs --local URL or --stdio")
		return c, apperr.ExitCLIValidation
	}
	if c.localURL != "" && c.stdio {
		fmt.Fprintln(os.Stderr, "pick one of --local or --stdio")
		return c, apperr.ExitCLIValidation
	}
	// Remote publication of operator-selected subprocesses is disabled
	// (P0-1, P0-2): the stdio bridge cannot enforce upstream OAuth, and
	// the anonymous fixture profile cannot bound an arbitrary child, so
	// neither auth mode is safe with --stdio. This stays rejected until
	// the P0-C bridge lands with protocol and auth enforcement. Publish
	// an HTTP-native loopback MCP server with --local, or run a child
	// loopback-only via `mcp expose` (never remotely reachable).
	if c.stdio {
		fmt.Fprintln(os.Stderr, "mcp publish --stdio is disabled: the stdio bridge cannot enforce MCP authentication yet; publish --local http://127.0.0.1:PORT/mcp instead")
		return c, apperr.ExitCLIValidation
	}
	// Anonymous fixtures cannot be published (P0-F): the profile
	// cannot bound an arbitrary local server, so it must never back a
	// public route. Local-only lifecycle (serve) and diagnostics keep
	// accepting it; publish requires --auth upstream-oauth.
	if !serve && c.auth == "fixture-anonymous" {
		fmt.Fprintln(os.Stderr, "mcp publish --auth fixture-anonymous is disabled: anonymous fixtures cannot be published; use `mcp serve --auth fixture-anonymous` for local-only fixtures or publish --auth upstream-oauth")
		return c, apperr.ExitCLIValidation
	}
	// --strict-discovery only constrains route publication; serve has
	// no route and no discovery, so the combination is rejected
	// rather than silently ignored.
	if serve && c.strictDiscovery {
		fmt.Fprintln(os.Stderr, "mcp serve takes no --strict-discovery: discovery qualification applies to publish only")
		return c, apperr.ExitCLIValidation
	}
	return c, 0
}

// errDiscoveryUnreachable marks an inconclusive OAuth discovery probe:
// the metadata endpoint could not be reached, so its advertised resource
// is NOT VERIFIED (not proven wrong). Callers warn loudly and continue
// instead of failing closed on publisher network position.
var errDiscoveryUnreachable = errors.New("oauth discovery unreachable")

// mcpRouteDiscoveryURL derives the RFC 9728 well-known URL for a
// relay-minted route URL of the exact shape
// https://<host>/r/<route-id>/mcp. The scheme/host/path contract is the
// relay's (serveMCPRouteMutation mints it); anything else fails closed
// rather than probing an attacker-shaped URL.
func mcpRouteDiscoveryURL(routeURL, routeID string) (string, error) {
	u, err := url.Parse(routeURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("route URL is not a valid https URL: %q", routeURL)
	}
	if u.EscapedPath() != "/r/"+routeID+"/mcp" {
		return "", fmt.Errorf("route URL %q does not match route %q", routeURL, routeID)
	}
	return "https://" + u.Host + "/.well-known/oauth-protected-resource/r/" + routeID + "/mcp", nil
}

// validateMCPResourceMetadata fetches an RFC 9728 protected-resource
// metadata document and requires its advertised "resource" to equal the
// published route URL exactly (P0-E). A reachable document naming a
// different resource fails closed: the upstream would authorize tokens
// for the wrong endpoint. Transport failure is inconclusive
// (errDiscoveryUnreachable), never proof of either validity or attack.
func validateMCPResourceMetadata(client *http.Client, discoveryURL, expectResource string) error {
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("%w: %v", errDiscoveryUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("%w: unreadable discovery body", errDiscoveryUnreachable)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth discovery answered %d (want 200 with resource %q)", resp.StatusCode, expectResource)
	}
	var doc struct {
		Resource string `json:"resource"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Resource == "" {
		return fmt.Errorf("oauth discovery is not a resource metadata document")
	}
	if doc.Resource != expectResource {
		return fmt.Errorf("upstream advertises resource %q, published route is %q", doc.Resource, expectResource)
	}
	return nil
}

// mcpAccessMode maps the --auth profile to the lease access mode born
// at allocation (P1). The strings duplicate relay constants by design:
// the CLI submits its intent and the relay validates it authoritatively.
func mcpAccessMode(auth string) string {
	if auth == "fixture-anonymous" {
		return "mcp_anonymous_fixture"
	}
	return "mcp_upstream_oauth"
}

// parseMCPLocalURL validates a --local value: http on a loopback host
// with an explicit port, serving exactly /mcp (the only backend path a
// route forwards). Userinfo, query, and fragments have no publishing
// semantics and are rejected rather than silently dropped. The loopback
// family is reported so the probe and tunnel honor an IPv6-only server
// instead of failing against 127.0.0.1 (P2-1). Anything else fails
// before any tunnel or route exists.
func parseMCPLocalURL(raw string) (port int, v6 bool, err error) {
	u, perr := url.Parse(raw)
	if perr != nil {
		return 0, false, fmt.Errorf("invalid --local URL: %v", perr)
	}
	if u.Scheme != "http" {
		return 0, false, fmt.Errorf("--local must be http (loopback): %q", raw)
	}
	if u.User != nil {
		return 0, false, fmt.Errorf("--local must not carry userinfo: %q", raw)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return 0, false, fmt.Errorf("--local must not carry a query string: %q", raw)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return 0, false, fmt.Errorf("--local must not carry a fragment: %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "127.0.0.1", "localhost":
	case "::1":
		v6 = true
	default:
		return 0, false, fmt.Errorf("--local must be loopback, got host %q", u.Hostname())
	}
	p := strings.TrimSuffix(u.Path, "/")
	if p != "/mcp" {
		return 0, false, fmt.Errorf("--local path must be /mcp (the route forwards exactly /mcp), got %q", u.Path)
	}
	portStr := u.Port()
	if portStr == "" {
		return 0, false, fmt.Errorf("--local needs an explicit port: %q", raw)
	}
	n, cerr := strconv.Atoi(portStr)
	if cerr != nil || n <= 0 || n > 65535 {
		return 0, false, fmt.Errorf("invalid --local port: %q", raw)
	}
	return n, v6, nil
}

// mcpTunnelOptions reuses the ordinary tunnel flag parser (config file,
// env, and defaults precedence included) with the MCP port and mode
// applied. `ocliv PORT` never sets AccessMode; only publish/serve do.
func mcpTunnelOptions(port int, v6 bool, c mcpPublishConfig) (tunnelOptions, int) {
	argv := []string{strconv.Itoa(port)}
	if v6 {
		argv = append(argv, "--ipv6")
	}
	if c.name != "" {
		argv = append(argv, "--name="+c.name)
	}
	if c.ttl != "" {
		argv = append(argv, "--ttl="+c.ttl)
	}
	opts, code := parseTunnelOptions(argv)
	if code != 0 {
		return opts, code
	}
	opts.cfg.AccessMode = mcpAccessMode(c.auth)
	// Bounded default lease TTL (P1-8): an MCP publication without an
	// explicit --ttl (or config default_ttl) expires after 12h, so a
	// failed remote close cannot leave an indefinite exposure window.
	// Pass --ttl explicitly for longer-lived hosting.
	if opts.cfg.TTLSeconds == 0 {
		opts.cfg.TTLSeconds = 12 * 3600
	}
	return opts, 0
}

func cmdMCPPublish(argv []string) int {
	return runMCPPublish(argv, false)
}

func cmdMCPServe(argv []string) int {
	return runMCPPublish(argv, true)
}

// runMCPPublish owns the full lifecycle: optional stdio child, tunnel in
// the requested mode, optional route registration, steady state, and
// ordered cleanup with independently recorded outcomes.
func runMCPPublish(argv []string, serve bool) int {
	cfg, code := parseMCPPublish(argv, serve)
	if code != 0 {
		return code
	}
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	relayURL := agentRelayURL()

	// 1. Local source: validate and start before any tunnel or route, so
	// a bad local target fails with nothing registered remotely.
	// --stdio is rejected in parseMCPPublish (the stdio bridge cannot
	// enforce MCP authentication yet), so only --local reaches here.
	port := 0
	v6 := false
	{
		var perr error
		port, v6, perr = parseMCPLocalURL(cfg.localURL)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "mcp publish: %v\n", perr)
			return apperr.ExitCLIValidation
		}
		target := config.LoopbackTarget(port, v6)
		if perr := agent.ProbeLocal(target, 3*time.Second); perr != nil {
			fmt.Fprintf(os.Stderr, "local MCP unreachable at %s: %v\n", target, perr)
			return apperr.ExitLocalTarget
		}
		// The local endpoint must speak MCP before a public route is
		// registered for it (P1). An upstream-oauth server that
		// answers with an authentication challenge is sufficient
		// presence — tool functionality is never claimed from a
		// challenge.
		pout := runMCPProbe(target, mcpAccessMode(cfg.auth))
		if !pout.Verified && !(pout.Auth == "AUTH_REQUIRED" && cfg.auth == "upstream-oauth") {
			fmt.Fprintf(os.Stderr, "local MCP %s failed protocol check: %s\n", target, pout.Summary)
			return apperr.ExitLocalTarget
		}
		fmt.Printf("local MCP: %s\n", pout.Summary)
	}

	// 2. Tunnel in the requested mode.
	opts, tcode := mcpTunnelOptions(port, v6, cfg)
	if tcode != 0 {
		return tcode
	}
	ready, pcode := prepareTunnel(opts)
	if pcode != 0 {
		return pcode
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, live, rcode, ok := runTunnel(ctx, ready)
	if !ok {
		return rcode
	}
	if a.AccessMode != mcpAccessMode(cfg.auth) {
		fmt.Fprintf(os.Stderr, "mcp publish: relay allocated mode %q, want %q; refusing to publish\n",
			a.AccessMode, mcpAccessMode(cfg.auth))
		return closeTunnel(ready, a, apperr.ExitAuth)
	}
	renderTunnelAttached(ready, a)

	// 3. Route registration (publish only): after attachment, so the
	// printed endpoint is live, never speculative.
	var routeID, routeURL, routeLeaseID string
	if !serve {
		profile := cfg.auth
		// The route is owned by the lease that exists at registration
		// time; runSteadyState may re-assign a to a newer attachment, so
		// the DELETE below must use this ID, not the updated a.LeaseID.
		routeLeaseID = a.LeaseID
		rstatus, rbody := mgmtCall(relayURL, k, keyID, "POST",
			"/v1/agent/lease/"+routeLeaseID+"/mcp-route/"+profile)
		if rstatus != http.StatusOK {
			fmt.Fprintf(os.Stderr, "mcp publish: route registration failed (relay status %d): %s\n",
				rstatus, strings.TrimSpace(string(rbody)))
			return closeTunnel(ready, a, apperr.ExitAuth)
		}
		var rr struct {
			RouteID string `json:"route_id"`
			URL     string `json:"url"`
			Auth    string `json:"auth"`
		}
		if jerr := json.Unmarshal(rbody, &rr); jerr != nil || rr.RouteID == "" || rr.URL == "" {
			fmt.Fprintln(os.Stderr, "mcp publish: relay route reply unparseable")
			return closeTunnel(ready, a, apperr.ExitInternal)
		}
		routeID, routeURL = rr.RouteID, rr.URL
		fmt.Printf("\n✓ MCP route registered (auth: %s)\n", rr.Auth)
		fmt.Println(routeURL)
		// P0-E: for upstream-oauth publications, prove the upstream's
		// advertised OAuth resource is exactly this route before
		// serving it. The discovery document is fetched through the
		// live tunnel via the public path, so this also exercises
		// the route end to end. A mismatch fails closed (delete the
		// route, close the lease); an unreachable endpoint is
		// inconclusive and warns loudly instead of blocking on
		// publisher network position.
		if cfg.auth == "upstream-oauth" {
			durl, derr := mcpRouteDiscoveryURL(routeURL, routeID)
			if derr != nil {
				fmt.Fprintf(os.Stderr, "mcp publish: bad route URL from relay: %v\n", derr)
				del := func(path string) (int, string) {
					st, body := mgmtCall(relayURL, k, keyID, "DELETE", path)
					return st, string(body)
				}
				if dstatus, ddetail := abandonPublishedRoute(del, routeLeaseID, routeID); dstatus != http.StatusOK {
					fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete reported status %d (%s)\n", dstatus, ddetail)
				}
				routeID = ""
				return closeTunnel(ready, a, apperr.ExitInternal)
			}
			dclient := &http.Client{Timeout: 15 * time.Second}
			if derr := validateMCPResourceMetadata(dclient, durl, routeURL); derr != nil {
				if !discoveryFailureFatal(cfg, derr) {
					fmt.Fprintf(os.Stderr, "warning: mcp publish: OAuth discovery unreachable (%v); resource binding NOT verified\n", derr)
				} else {
					if errors.Is(derr, errDiscoveryUnreachable) {
						fmt.Fprintf(os.Stderr, "mcp publish: OAuth discovery unreachable and --strict-discovery set: refusing unproven binding: %v\n", derr)
					} else {
						fmt.Fprintf(os.Stderr, "mcp publish: OAuth discovery invalid: %v\n", derr)
					}
					del := func(path string) (int, string) {
						st, body := mgmtCall(relayURL, k, keyID, "DELETE", path)
						return st, string(body)
					}
					if dstatus, ddetail := abandonPublishedRoute(del, routeLeaseID, routeID); dstatus != http.StatusOK {
						fmt.Fprintf(os.Stderr, "warning: mcp publish: abort route delete reported status %d (%s)\n", dstatus, ddetail)
					}
					routeID = ""
					return closeTunnel(ready, a, apperr.ExitAuth)
				}
			} else {
				fmt.Println("✓ OAuth discovery verified (resource matches published URL)")
			}
		}
	}

	// 4. Steady state, then ordered cleanup with recorded outcomes.
	// Both remote revocations are attempted even if one fails; the exit
	// code reflects unconfirmed remote cleanup (P1-8).
	a, scode := runSteadyState(ctx, ready, live, a)
	res := CleanupResult{RouteDeleteStatus: -1}
	if !serve && routeID != "" {
		dstatus, dbody := mgmtCall(relayURL, k, keyID, "DELETE",
			"/v1/agent/lease/"+routeLeaseID+"/mcp-route/"+routeID)
		res.RouteID = routeID
		res.RouteDeleteStatus = dstatus
		res.RouteDetail = shortDetail(string(dbody))
		if dstatus == http.StatusOK {
			fmt.Println("✓ MCP route removed")
		}
	}
	leaseID := a.LeaseID
	if leaseID == "" {
		// No guessed close from the store's latest record (P1-1): that
		// could revoke another tunnel's lease. Mark the lease
		// unconfirmed so the exit is nonzero via res.ExitCode.
		fmt.Fprintln(os.Stderr, "warning: no live attachment lease ID; remote lease state unconfirmed (no close attempted)")
		res.LeaseCloseStatus = 0
		res.LeaseDetail = "no live attachment lease ID"
	} else {
		lr := closeLeaseWith(defaultLeaseCloser, ready, leaseID)
		res.LeaseID = lr.LeaseID
		res.LeaseCloseStatus = lr.LeaseCloseStatus
		res.LeaseDetail = lr.LeaseDetail
	}
	if msg := res.Report(); msg != "" {
		fmt.Fprint(os.Stderr, msg)
	}
	return res.ExitCode(scode)
}

// selectDoctorLeaseID resolves explicit --lease, named selection, and
// latest-lease fallback, in that order. A named lookup goes through the
// store first so a valid non-latest lease is accepted; the latest
// recorded lease is only a fallback when --name is empty. Mismatch fails
// closed so a diagnosis can never silently report on the wrong tunnel.
// Returns the lease ID, the exact stderr message, and the exit code.
func selectDoctorLeaseID(dir, name, explicitLease string) (string, string, int) {
	leaseID := explicitLease
	// --name selects by lease label and fails closed on mismatch.
	if name != "" {
		store, serr := config.OpenLeaseStore(dir)
		if serr != nil {
			return "", "no recorded lease; start a tunnel first\n", apperr.ExitCLIValidation
		}
		rec, err := store.FindByName(name)
		if err != nil {
			var amb *config.AmbiguousNameError
			if errors.As(err, &amb) {
				return "", fmt.Sprintf("ambiguous lease name %q: matches %s; use --lease ID\n",
					name, strings.Join(amb.Candidates, ", ")), apperr.ExitCLIValidation
			}
			return "", fmt.Sprintf("no recorded lease named %q\n", name), apperr.ExitCLIValidation
		}
		if explicitLease != "" && rec.LeaseID != explicitLease {
			// Explicit --lease wins; --name only cross-checks it.
			return "", fmt.Sprintf("no recorded lease named %q\n", name), apperr.ExitCLIValidation
		}
		leaseID = rec.LeaseID
	}
	if leaseID == "" {
		leaseID = lastLeaseID(dir)
	}
	if leaseID == "" {
		return "", "no recorded lease; start a tunnel first\n", apperr.ExitCLIValidation
	}
	return leaseID, "", 0
}

// doctorLoopbackTarget resolves the exact local probe target for a
// lease: the loopback family recorded at tunnel startup. An unknown
// record keeps the historical IPv4 default rather than probing both
// families and risking a same-port misdiagnosis (P1).
func doctorLoopbackTarget(dir, leaseID string, port int) string {
	if store, serr := config.OpenLeaseStore(dir); serr == nil {
		if rec, ok := store.Load(leaseID); ok && rec.IPv6 {
			return config.LoopbackTarget(port, true)
		}
	}
	return config.LoopbackTarget(port, false)
}

// cmdMCPDoctor reports enrollment, lease, route, local-service, and MCP
// protocol status from the authoritative sources. It prints no secrets:
// the status and route-listing endpoints carry none.
func cmdMCPDoctor(argv []string) int {
	leaseID := ""
	name := ""
	usage := "usage: ocliv mcp doctor [--lease ID] [--name LABEL]"
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--lease" || strings.HasPrefix(a, "--lease=") {
			v, ok := mcpFlagValue(argv, &i, "lease")
			if !ok {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			leaseID = v
		} else if a == "--name" || strings.HasPrefix(a, "--name=") {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				fmt.Fprintln(os.Stderr, usage)
				return apperr.ExitCLIValidation
			}
			name = v
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q (%s)\n", a, usage)
			return apperr.ExitCLIValidation
		}
	}
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	relayURL := agentRelayURL()
	dir, _, _, _ := agentFiles()
	leaseID, msg, code := selectDoctorLeaseID(dir, name, leaseID)
	if code != 0 {
		fmt.Fprint(os.Stderr, msg)
		return code
	}
	fmt.Println("enrollment: ok")

	scode, sbody := mgmtCall(relayURL, k, keyID, "GET", "/v1/agent/lease/"+leaseID+"/status")
	if scode != http.StatusOK {
		fmt.Printf("relay lease status: unreachable (relay status %d)\n", scode)
		fmt.Println("route status: unknown (relay unreachable)")
		fmt.Println("local service: unknown (no lease port)")
		fmt.Println("mcp protocol: unknown (no lease port)")
		return apperr.ExitRelayTLS
	}
	var st struct {
		Hostname   string `json:"hostname"`
		Port       int    `json:"port"`
		AccessMode string `json:"access_mode"`
		Status     string `json:"status"`
		Generation int64  `json:"generation"`
		RouteLive  bool   `json:"route_live"`
	}
	if jerr := json.Unmarshal(sbody, &st); jerr != nil {
		fmt.Fprintln(os.Stderr, "relay status reply unparseable")
		return apperr.ExitInternal
	}
	fmt.Printf("lease: %s status=%s mode=%s generation=%d\n", leaseID, st.Status, st.AccessMode, st.Generation)
	fmt.Printf("route live: %v\n", st.RouteLive)

	rcode, rbody := mgmtCall(relayURL, k, keyID, "GET", "/v1/agent/lease/"+leaseID+"/mcp-route")
	if rcode != http.StatusOK {
		fmt.Printf("routes: unknown (relay status %d)\n", rcode)
	} else {
		var rl struct {
			Routes []struct {
				RouteID string `json:"route_id"`
				Auth    string `json:"auth"`
				URL     string `json:"url"`
			} `json:"routes"`
		}
		if jerr := json.Unmarshal(rbody, &rl); jerr != nil {
			fmt.Fprintln(os.Stderr, "route list reply unparseable")
			return apperr.ExitInternal
		}
		if len(rl.Routes) == 0 {
			fmt.Println("routes: none")
		}
		for _, r := range rl.Routes {
			url := r.URL
			if url == "" {
				url = "(no external host configured)"
			}
			fmt.Printf("route: %s auth=%s\n  %s\n", r.RouteID, r.Auth, url)
		}
	}

	if st.Port <= 0 {
		fmt.Println("local service: unknown (no lease port)")
		fmt.Println("mcp protocol: unknown (no lease port)")
		return doctorProtocolExit(st.AccessMode, false)
	}
	target := doctorLoopbackTarget(dir, leaseID, st.Port)
	if perr := agent.ProbeLocal(target, 3*time.Second); perr != nil {
		fmt.Printf("local service: unreachable (%s)\n", target)
		fmt.Println("mcp protocol: unknown (local unreachable)")
		return apperr.ExitLocalTarget
	}
	fmt.Printf("local service: responsive (%s)\n", target)
	out := runMCPProbe(target, st.AccessMode)
	fmt.Printf("mcp protocol: %s\n", out.Summary)
	fmt.Printf("mcp auth: %s\n", doctorAuthLine(st.AccessMode, out.Auth))
	fmt.Println("chatgpt registration: EXTERNAL_UNVERIFIED (register the exact public URL in ChatGPT after external qualification)")
	return doctorProtocolExit(st.AccessMode, out.Verified)
}
