package cli

// `ocliv setup`: automated detection and bootstrapping of a self-hosted
// public relay. Slice 1 is detection-only: it classifies the host's
// inbound prospects (direct, NAT, CGNAT, unknown) and prints the
// concrete next steps. It changes nothing: no DNS updates, no router
// changes, no services, no credentials.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/relay"
	"ocliv/internal/setup"
	"ocliv/internal/store"
)

// setupManagedDestinations are the system files bootstrap may
// replace; every completed step failure rolls them back to the
// pre-install backups, and success cleans the backups up.
var setupManagedDestinations = []string{
	"/etc/caddy/Caddyfile",
	"/etc/systemd/system/ocliv-relay.service",
}

// Default echo endpoints observe the egress address per family. They
// are diagnostics-only (best effort, 8s each inside the 30s budget),
// receive no credentials, and can be overridden or disabled with empty
// --echo-v4/--echo-v6 values.
const (
	defaultEchoV4 = "https://api4.ipify.org"
	defaultEchoV6 = "https://api6.ipify.org"
)

func cmdSetup(argv []string) int {
	auto := true
	check := false
	jsonOut := false
	dryRun := false
	hostname := ""
	tokenFile := ""
	acmeEmail := ""
	outDir := ""
	dataDir := "/var/lib/ocliv"
	provider := ""
	compartment := ""
	zone := ""
	confirmCreate := false
	refreshDNS := false
	echoV4, echoV6 := defaultEchoV4, defaultEchoV6
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--auto":
			auto = true
		case a == "--check":
			check = true
			auto = false
		case a == "--json":
			jsonOut = true
		case a == "--dry-run":
			dryRun = true
		case a == "--refresh-dns":
			refreshDNS = true
		case strings.HasPrefix(a, "--hostname="):
			hostname = strings.TrimPrefix(a, "--hostname=")
		case a == "--hostname" && i+1 < len(argv):
			i++
			hostname = argv[i]
		case strings.HasPrefix(a, "--token-file="):
			tokenFile = strings.TrimPrefix(a, "--token-file=")
		case a == "--token-file" && i+1 < len(argv):
			i++
			tokenFile = argv[i]
		case strings.HasPrefix(a, "--acme-email="):
			acmeEmail = strings.TrimPrefix(a, "--acme-email=")
		case a == "--acme-email" && i+1 < len(argv):
			i++
			acmeEmail = argv[i]
		case strings.HasPrefix(a, "--out="):
			outDir = strings.TrimPrefix(a, "--out=")
		case a == "--out" && i+1 < len(argv):
			i++
			outDir = argv[i]
		case strings.HasPrefix(a, "--data-dir="):
			dataDir = strings.TrimPrefix(a, "--data-dir=")
		case a == "--data-dir" && i+1 < len(argv):
			i++
			dataDir = argv[i]
		case strings.HasPrefix(a, "--provider="):
			provider = strings.TrimPrefix(a, "--provider=")
		case a == "--provider" && i+1 < len(argv):
			i++
			provider = argv[i]
		case strings.HasPrefix(a, "--compartment="):
			compartment = strings.TrimPrefix(a, "--compartment=")
		case a == "--compartment" && i+1 < len(argv):
			i++
			compartment = argv[i]
		case strings.HasPrefix(a, "--availability-domain="):
			zone = strings.TrimPrefix(a, "--availability-domain=")
		case a == "--availability-domain" && i+1 < len(argv):
			i++
			zone = argv[i]
		case a == "--confirm-create":
			confirmCreate = true
		case strings.HasPrefix(a, "--echo-v4="):
			echoV4 = strings.TrimPrefix(a, "--echo-v4=")
		case a == "--echo-v4" && i+1 < len(argv):
			i++
			echoV4 = argv[i]
		case strings.HasPrefix(a, "--echo-v6="):
			echoV6 = strings.TrimPrefix(a, "--echo-v6=")
		case a == "--echo-v6" && i+1 < len(argv):
			i++
			echoV6 = argv[i]
		default:
			fmt.Fprintf(os.Stderr, "unknown setup flag %q; see `ocliv help`\n", a)
			return apperr.ExitCLIValidation
		}
	}
	if dryRun && hostname == "" {
		fmt.Fprintln(os.Stderr, "--dry-run needs --hostname ZONE.dynv6.net")
		return apperr.ExitCLIValidation
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d := setup.Gather(ctx, echoV4, echoV6)
	if jsonOut {
		raw, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		fmt.Println(string(raw))
		return apperr.ExitOK
	}
	printSetupReport(d)
	if refreshDNS {
		if hostname == "" {
			fmt.Fprintln(os.Stderr, "--refresh-dns needs --hostname ZONE.dynv6.net")
			return apperr.ExitCLIValidation
		}
		return runSetupRefreshDNS(ctx, hostname, tokenFile, echoV4, echoV6)
	}
	if check || !auto {
		return apperr.ExitOK
	}
	if provider != "" {
		return runSetupProvider(ctx, d, provider, compartment, zone, confirmCreate)
	}
	if hostname == "" {
		printSetupNext(d)
		return apperr.ExitOK
	}
	return runSetupDNS(ctx, d, hostname, tokenFile, acmeEmail, outDir, dataDir, dryRun)
}

// runSetupDNS syncs the dynv6 zone to the observed egress addresses.
// The token comes from DYNV6_TOKEN or an owner-only --token-file, never
// from argv, logs, or errors. --dry-run prints the exact update with
// the token redacted and sends nothing. With --acme-email, a successful
// update additionally renders the single-host deployment, verifies the
// name resolves to the observed egress, and persists relay_url for
// `ocliv 3000` / `mcp publish`; nothing is activated yet.
// runSetupRefreshDNS performs one check-and-update DNS cycle without
// touching Caddy, systemd, or enrollment: suitable for cron or a
// systemd timer between full `setup --auto` runs. The relay keeps
// serving throughout; only the DNS record changes.
func runSetupRefreshDNS(ctx context.Context, hostname, tokenFile, echoV4, echoV6 string) int {
	token, code := readDynv6Token(tokenFile, hostname)
	if code != apperr.ExitOK {
		return code
	}
	changed, err := setup.RefreshDynDNS(ctx, dynv6Endpoint(), hostname, token, echoV4, echoV6)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return apperr.ExitRelayTLS
	}
	if changed {
		fmt.Printf("dns refreshed for %s (address changed)\n", hostname)
	} else {
		fmt.Printf("dns already current for %s; no update sent\n", hostname)
	}
	return apperr.ExitOK
}

// readDynv6Token resolves the provider credential from DYNV6_TOKEN or
// an owner-only --token-file. The token never comes from argv.
func readDynv6Token(tokenFile, hostname string) (string, int) {
	token := strings.TrimSpace(os.Getenv("DYNV6_TOKEN"))
	if tokenFile != "" {
		fi, err := os.Stat(tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read --token-file: %v\n", err)
			return "", apperr.ExitCLIValidation
		}
		if fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "error: token file %q is group/other-readable (want 0600); fix permissions first\n", tokenFile)
			return "", apperr.ExitCLIValidation
		}
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read --token-file: %v\n", err)
			return "", apperr.ExitCLIValidation
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		fmt.Fprintf(os.Stderr, "dynv6 HTTP token needed for %q: create one at https://dynv6.com/keys (HTTP token for the zone), then export DYNV6_TOKEN or pass --token-file PATH (0600)\n", hostname)
		return "", apperr.ExitAuth
	}
	return token, apperr.ExitOK
}

func runSetupDNS(ctx context.Context, d setup.Detection, hostname, tokenFile, acmeEmail, outDir, dataDir string, dryRun bool) int {
	token, code := readDynv6Token(tokenFile, hostname)
	if code != apperr.ExitOK {
		return code
	}
	endpoint := dynv6Endpoint()
	fmt.Printf("dns update: %s -> v4=%s v6=%s (token from %s, redacted)\n",
		hostname, nonEmpty(d.EgressV4), nonEmpty(d.EgressV6), tokenSource(tokenFile))
	if dryRun {
		fmt.Printf("dry-run: no request sent\n")
		return apperr.ExitOK
	}
	if err := setup.UpdateDynv6(ctx, endpoint, hostname, token, d.EgressV4, d.EgressV6); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return apperr.ExitRelayTLS
	}
	fmt.Printf("dns updated for %s; verify with: dig +short %s A; dig +short %s AAAA\n", hostname, hostname, hostname)
	if acmeEmail == "" {
		return apperr.ExitOK
	}
	return runSetupRender(ctx, d, hostname, acmeEmail, outDir, dataDir)
}

// runSetupRender generates the reviewable single-host deployment for
// the dynv6 hostname, self-checks it, confirms the name resolves to
// the observed egress, and only then persists relay_url. Caddy,
// systemd, and enrollment stay manual until the next slice automates
// them; this function activates nothing.
func runSetupRender(ctx context.Context, d setup.Detection, hostname, acmeEmail, outDir, dataDir string) int {
	dir, _, _, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	if outDir == "" {
		outDir = filepath.Join(dir, "setup-"+strings.ToLower(hostname))
	}
	initArgv := []string{"--domain", hostname, "--edge", "tunnel", "--mcp-host", hostname,
		"--acme-email", acmeEmail, "--out", outDir}
	if code := cmdRelayInit(initArgv); code != apperr.ExitOK {
		return code
	}
	if bad := checkInitDir(outDir); len(bad) > 0 {
		for _, line := range bad {
			fmt.Fprintln(os.Stderr, "init check: "+line)
		}
		return apperr.ExitInternal
	}
	matched, addrs, err := verifyDNSResolution(ctx, hostname, []string{d.EgressV4, d.EgressV6})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns for %s not resolving here yet (%v); wait for propagation, then re-run `ocliv setup --auto --hostname %s --acme-email %s`\n", hostname, err, hostname, acmeEmail)
		return apperr.ExitRelayTLS
	}
	if !matched {
		fmt.Fprintf(os.Stderr, "dns for %s resolves to %s here, not to observed egress %s/%s; refusing to persist an unverified endpoint (propagation delay or wrong zone?)\n",
			hostname, strings.Join(addrs, ","), nonEmpty(d.EgressV4), nonEmpty(d.EgressV6))
		return apperr.ExitRelayTLS
	}
	// The tunnel edge also serves per-tunnel hostnames under
	// *.t.<domain> (on-demand ACME). An apex A/AAAA update is not
	// wildcard provisioning: prove a fresh tunnel hostname resolves
	// here before claiming the deployment is complete.
	if wmatched, _, werr := verifyWildcardDNS(ctx, hostname, []string{d.EgressV4, d.EgressV6}); werr != nil || !wmatched {
		fmt.Fprintf(os.Stderr, "ACTION REQUIRED: *.t.%s does not resolve to this host here", hostname)
		if werr != nil {
			fmt.Fprintf(os.Stderr, " (%v)", werr)
		}
		fmt.Fprintf(os.Stderr, "; tunnel hostnames like <id>.t.%s would not validate.\n", hostname)
		fmt.Fprintf(os.Stderr, "ACTION REQUIRED: create one wildcard record — *.t.%s A %s%s — then re-run `ocliv setup --auto --hostname %s --acme-email %s`\n",
			hostname, nonEmpty(d.EgressV4), wildcardAAAASuffix(d.EgressV6), hostname, acmeEmail)
		return apperr.ExitRelayTLS
	}
	_, _, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	relayURL := "https://" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	existing := readExistingRelayURL(cfgPath)
	// The rendered deployment in outDir is the *candidate* setup; the
	// recorded relay_url is the *active* client configuration. The
	// candidate becomes active only after provisioning succeeds —
	// never on DNS verification alone, which proves nothing about
	// Caddy, relay startup, or enrollment.
	fmt.Printf("deployment rendered to %s (candidate; active relay_url unchanged: %s)\n", outDir, nonEmpty(existing))
	code, completed := runSetupBootstrap(d, hostname, outDir, dataDir)
	if code == apperr.ExitOK && completed && shouldPersistRelayURL(existing, relayURL, completed) {
		if err := mergeRelayURL(cfgPath, relayURL); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		fmt.Printf("provisioning complete; relay_url now %s\n", relayURL)
	} else if code == apperr.ExitOK && completed {
		fmt.Printf("provisioning complete; relay_url unchanged\n")
	} else {
		fmt.Printf("provisioning incomplete; working relay_url (%s) retained — artifacts kept in %s for inspection\n", nonEmpty(existing), outDir)
	}
	return code
}

// shouldPersistRelayURL decides whether a newly rendered endpoint may
// replace the recorded client setting. Only completed provisioning
// qualifies: a failed Caddy install, relay start, or enrollment must
// never strand the client on a dead endpoint, and a fresh install
// must not record an endpoint that was never provisioned.
func shouldPersistRelayURL(existing, next string, provisioned bool) bool {
	// existing is accepted but unused in the decision: fresh, same,
	// and replacement URLs all persist exactly when provisioning
	// completed. It stays a parameter so the call site documents
	// which working configuration is being replaced.
	return next != "" && provisioned
}

// readExistingRelayURL returns the recorded relay_url, or "" when the
// agent config has none. Unreadable files fail closed to "" only for
// missing files; other errors surface to the caller via merge errors.
func readExistingRelayURL(cfgPath string) string {
	vals, err := config.LoadAgentFile(cfgPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(vals["relay_url"])
}

// verifyWildcardDNS proves the tunnel namespace resolves here: it
// looks up a fresh random <label>.t.<domain> (never a cached real
// lease name) and requires it to hit the observed egress. A miss
// means the wildcard record is absent, not merely slow apex
// propagation — the apex check already passed above.
func verifyWildcardDNS(ctx context.Context, hostname string, want []string) (bool, []string, error) {
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return false, nil, err
	}
	probe := "ocliv-probe-" + hex.EncodeToString(rnd[:]) + ".t." + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	return verifyDNSResolution(ctx, probe, want)
}

func wildcardAAAASuffix(v6 string) string {
	if strings.TrimSpace(v6) == "" {
		return ""
	}
	return " + AAAA " + v6
}

// runSetupBootstrap executes the viable-path edge plan. Only steps the
// planner marks auto run, and only as root; everything else prints as
// the exact manual command. Live executors back up before replacing.
// It returns the exit code plus whether provisioning actually
// completed: manual-only plans and hard blocks report ACTION_REQUIRED
// (ExitRelayTLS), never success, so callers never treat a printed
// plan as a functioning tunnel.
func runSetupBootstrap(d setup.Detection, hostname, deployDir, dataDir string) (int, bool) {
	_, caddyErr := exec.LookPath("caddy")
	env := setup.BootstrapEnv{
		AsRoot:       os.Geteuid() == 0,
		CaddyPresent: caddyErr == nil,
		Path:         d.Path,
		Hostname:     hostname,
		DeployDir:    deployDir,
	}
	steps, blockReason := setup.PlanBootstrap(env)
	if blockReason != "" && len(steps) == 0 {
		fmt.Printf("ACTION REQUIRED: edge provisioning blocked: %s\n", blockReason)
		return apperr.ExitRelayTLS, false
	}
	allAuto := true
	for _, s := range steps {
		if !s.Auto {
			allAuto = false
			fmt.Printf("manual: %s\n  %s\n", s.Title, s.Manual)
			continue
		}
		fmt.Printf("auto: %s ... ", s.Title)
		var err error
		switch s.Title {
		case "install Caddyfile":
			err = setup.InstallCaddyfile(deployDir)
		case "install systemd unit":
			err = setup.InstallUnit(deployDir)
		case "enable and start relay":
			err = setup.StartRelay()
		case "enroll this machine":
			keyID, exit := autoEnroll("https://"+hostname, dataDir, "home")
			if exit != apperr.ExitOK {
				err = fmt.Errorf("enrollment failed (exit %d)", exit)
			} else if keyID != "" {
				fmt.Printf("enrolled as %s ", keyID)
			} else {
				fmt.Printf("already enrolled, key untouched ")
			}
		default:
			err = fmt.Errorf("unknown step %q", s.Title)
		}
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			fmt.Printf("manual recovery: %s\n  %s\n", s.Title, s.Manual)
			// A later step failed after earlier steps replaced
			// system files: roll back to the pre-install
			// configuration instead of leaving a half-install.
			// Newly created files are removed entirely; rollback
			// failures are reported, never silently ignored.
			rollbackFailed := false
			restoredAny := false
			for _, dst := range setupManagedDestinations {
				restored, rerr := setup.RollbackInstalled(dst)
				if rerr != nil {
					fmt.Printf("rollback FAILED for %s: %v\n", dst, rerr)
					rollbackFailed = true
				}
				restoredAny = restoredAny || restored
			}
			if rollbackFailed {
				fmt.Printf("manual recovery: inspect backups (*.ocliv-bak) and journal (*.ocliv-new) beside the destinations above, restore by hand, then re-run\n")
			} else if restoredAny {
				// The unit install reloads the manager at install
				// time; re-read the restored files so the daemon
				// does not keep the rolled-back config in memory.
				if rerr := setup.ReloadServiceManager(); rerr != nil {
					fmt.Printf("warning: service-manager reload after rollback failed: %v\n", rerr)
				}
			}
			return apperr.ExitInternal, false
		}
		fmt.Printf("done\n")
	}
	// Single-manual-step plans (e.g. install Caddy first) block with
	// the re-run guidance instead of claiming progress.
	if blockReason != "" {
		fmt.Printf("ACTION REQUIRED: %s\n", blockReason)
		return apperr.ExitRelayTLS, false
	}
	if !allAuto {
		fmt.Printf("ACTION REQUIRED: %d step(s) need the operator (see manual commands above); re-run after completing them\n", len(steps))
		return apperr.ExitRelayTLS, false
	}
	for _, dst := range setupManagedDestinations {
		setup.CleanInstallBackup(dst)
	}
	fmt.Printf("verify externally: from another network, curl -v https://%s/v1/agent/challenge (no -k)\n", hostname)
	return apperr.ExitOK, true
}

// mintSetupCode mints a one-time enrollment code against the relay's
// own store. It opens the store directly (never constructs a Server,
// which would reconcile unrelated live lease rows) and never prints
// the code: it flows straight into the enroll exchange below.
func mintSetupCode(dataDir, tenant string) (string, error) {
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		return "", err
	}
	defer db.Close()
	return relay.IssueEnrollmentCode(db, tenant, time.Hour, "setup")
}

// autoEnroll completes enrollment against the just-provisioned relay:
// mint a code from the relay store, exchange it for registration.
// Already-enrolled machines are left untouched and report success with
// an empty key id. The enroll POST itself proves the full chain
// (DNS → Caddy → loopback relay) works.
func autoEnroll(relayURL, dataDir, tenant string) (string, int) {
	_, keyPath, _, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return "", apperr.ExitInternal
	}
	if _, err := os.Stat(keyPath); err == nil {
		return "", apperr.ExitOK
	}
	code, err := mintSetupCode(dataDir, tenant)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot mint enrollment code: "+err.Error())
		return "", apperr.ExitAuth
	}
	return performEnroll(relayURL, code, "")
}

// runSetupProvider handles the provider-relay path for hosts with no
// direct inbound route. With a viable local path the provider is
// unnecessary, so it says so and stops. Otherwise it checks the
// operator's own cloud tooling, prints the free-tier plan, and creates
// only with explicit --confirm-create plus compartment and zone.
func runSetupProvider(ctx context.Context, d setup.Detection, provider, compartment, zone string, confirm bool) int {
	if provider != "oracle" {
		fmt.Fprintf(os.Stderr, "unknown provider %q (supported: oracle)\n", provider)
		return apperr.ExitCLIValidation
	}
	if d.Path == setup.PathDirectV6 || d.Path == setup.PathDirectV4 || d.Path == setup.PathNATV4 {
		fmt.Printf("local path is %s: self-hosting directly is simpler and free — omit --provider to bootstrap here\n", d.Path)
		return apperr.ExitOK
	}
	a := setup.OracleAdapter{Compartment: compartment, Zone: zone}
	msg, ok := a.Check(ctx)
	fmt.Println(msg)
	if !ok {
		return apperr.ExitOK
	}
	fmt.Println(a.Plan())
	if err := a.Create(ctx, confirm); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		if !confirm {
			return apperr.ExitOK
		}
		return apperr.ExitInternal
	}
	fmt.Println("instance launch requested; continue in the OCI console, then point DNS at its public IP and re-run setup without --provider")
	return apperr.ExitOK
}

func tokenSource(tokenFile string) string {
	if tokenFile != "" {
		return "--token-file"
	}
	return "DYNV6_TOKEN"
}

// dynv6Endpoint is the update API base. OCLIV_DYNV6_ENDPOINT overrides
// it for hermetic tests; production always uses the provider default.
func dynv6Endpoint() string {
	if v := strings.TrimSpace(os.Getenv("OCLIV_DYNV6_ENDPOINT")); v != "" {
		return v
	}
	return setup.Dynv6UpdateEndpoint
}

// setupLookupHost resolves a name via the local resolver. It is a var
// so tests can stub DNS without network access.
var setupLookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// verifyDNSResolution reports whether hostname currently resolves (from
// this machine's resolver) to one of the observed egress addresses.
// A miss usually means propagation delay, not a failed update.
func verifyDNSResolution(ctx context.Context, hostname string, want []string) (matched bool, addrs []string, err error) {
	addrs, err = setupLookupHost(ctx, hostname)
	if err != nil {
		return false, nil, err
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		if w != "" {
			wantSet[w] = true
		}
	}
	for _, a := range addrs {
		if wantSet[a] {
			return true, addrs, nil
		}
	}
	return false, addrs, nil
}

func printSetupReport(d setup.Detection) {
	fmt.Printf("path: %s\n", d.Path)
	fmt.Printf("egress v4: %s  egress v6: %s\n", nonEmpty(d.EgressV4), nonEmpty(d.EgressV6))
	fmt.Printf("local v4: %s\n", strings.Join(d.LocalV4, ", "))
	fmt.Printf("local v6: %s\n", strings.Join(d.LocalV6, ", "))
	fmt.Printf("cgnat v4: %v  direct v4: %v  direct v6: %v\n", d.CGNATv4, d.DirectV4, d.DirectV6)
	fmt.Printf("inbound: UNKNOWN (outbound echo does not prove inbound reachability)\n")
	for _, n := range d.Notes {
		fmt.Printf("- %s\n", n)
	}
}

// printSetupNext gives the concrete next steps for the detected path.
// These are manual until provisioning slices automate them; each step
// names the exact permission or account action the operator must take.
func printSetupNext(d setup.Detection) {
	fmt.Printf("\nnext:\n")
	switch d.Path {
	case setup.PathDirectV6, setup.PathDirectV4:
		fam := "IPv6"
		if d.Path == setup.PathDirectV4 {
			fam = "IPv4"
		}
		fmt.Printf("- Pick a free DNS name (e.g. a dynv6 hostname) and point it at this host's public %s address.\n", fam)
		fmt.Printf("- Allow TCP 80/443 inbound in the host firewall; this host can serve directly (relay stays on 127.0.0.1, Caddy terminates TLS).\n")
		fmt.Printf("- Re-run `ocliv setup --auto` once DNS resolves here; provisioning continues from the stored detection.\n")
	case setup.PathNATV4:
		fmt.Printf("- In the router admin page, forward TCP 80 and 443 to this host (%s).\n", firstOr(d.LocalV4, "its LAN address"))
		fmt.Printf("- Pick a free DNS name (e.g. dynv6) pointing at the router's public IPv4; keep it updated if the address changes.\n")
		fmt.Printf("- Re-run `ocliv setup --auto` after the forward is in place.\n")
	case setup.PathCGNAT:
		fmt.Printf("- No direct IPv4 inbound path exists (carrier-grade NAT): port forwarding cannot work.\n")
		if d.DirectV6 || d.EgressV6 != "" {
			fmt.Printf("- IPv6 egress was observed: if the address is stable and globally reachable, serve over IPv6 (see the direct path above).\n")
		}
		fmt.Printf("- Otherwise a provider-hosted relay is required; that adapter is not implemented yet.\n")
	default:
		fmt.Printf("- Egress could not be observed: check network connectivity, then re-run `ocliv setup --check`.\n")
	}
}

func nonEmpty(s string) string {
	if s == "" {
		return "(unobserved)"
	}
	return s
}

func firstOr(ss []string, fallback string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return fallback
}
