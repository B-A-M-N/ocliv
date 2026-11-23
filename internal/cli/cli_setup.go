package cli

// `ocliv setup`: automated detection and bootstrapping of a self-hosted
// public relay. Slice 1 is detection-only: it classifies the host's
// inbound prospects (direct, NAT, CGNAT, unknown) and prints the
// concrete next steps. It changes nothing: no DNS updates, no router
// changes, no services, no credentials.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/setup"
)

// setupManagedDestinations are the system files bootstrap may
// replace; every completed step failure rolls them back to the
// pre-install backups, and success cleans the backups up. The set is
// the COMPLETE clean-host artifact list: without the binary,
// launcher, and environment file the unit cannot run at all, so a
// bootstrap that installed only the Caddyfile and unit left a fresh
// host unable to start (2026-11-13 clean-host completion).
var setupManagedDestinations = []string{
	"/etc/caddy/Caddyfile",
	"/etc/ocliv/relay.env",
	"/etc/ocliv/dns-refresh.env",
	"/usr/local/bin/ocliv-relay-launch.sh",
	"/etc/systemd/system/ocliv-relay.service",
	"/etc/systemd/system/ocliv-dns-refresh.service",
	"/etc/systemd/system/ocliv-dns-refresh.timer",
}

// Default echo endpoints observe the egress address per family. They
// are diagnostics-only (best effort, 8s each inside the 30s budget),
// receive no credentials, and can be overridden or disabled with empty
// --echo-v4/--echo-v6 values.
const (
	defaultEchoV4           = "https://api4.ipify.org"
	defaultEchoV6           = "https://api6.ipify.org"
	setupStateSchemaVersion = 2
	setupTemplateVersion    = 2
	defaultEdgeMode         = "wildcard"
)

// DefaultEdgeMode is the single-source default edge topology used by setup
// execution, recommendations, help text, and documentation (A11).
func DefaultEdgeMode() string { return defaultEdgeMode }

// Explicit setup state-machine stages (A9).
// stageEnrollmentComplete is intentionally absent: relay provisioning no
// longer enrolls a publisher. The relay is a separate role from publishers.
const (
	stageDetected          = "DETECTED"
	stageDNSUpdated        = "DNS_UPDATED"
	stageDNSVerified       = "DNS_VERIFIED"
	stageArtifactsRendered = "ARTIFACTS_RENDERED"
	stageSystemInstalled   = "SYSTEM_INSTALLED"
	stageRelayReady        = "RELAY_READY"
	stageRefreshTimerReady = "REFRESH_TIMER_READY"
	stageComplete          = "COMPLETE"
)

var setupStageOrder = []string{
	stageDetected,
	stageDNSUpdated,
	stageDNSVerified,
	stageArtifactsRendered,
	stageSystemInstalled,
	stageRelayReady,
	stageRefreshTimerReady,
	stageComplete,
}

func setupStageIndex(stage string) int {
	s := strings.ToUpper(strings.TrimSpace(stage))
	for i, candidate := range setupStageOrder {
		if candidate == s {
			return i
		}
	}
	return -1
}

// setupState persists versioned non-secret setup progress at
// <configDir>/setup-state.json so an interrupted `ocliv setup` can revalidate
// external evidence and resume cleanly without persisting raw credentials.
type setupState struct {
	SchemaVersion   int               `json:"schema_version"`
	TemplateVersion int               `json:"template_version,omitempty"`
	Fingerprint     string            `json:"fingerprint,omitempty"`
	DetectedPath    string            `json:"detected_path,omitempty"`
	Hostname        string            `json:"hostname,omitempty"`
	EdgeMode        string            `json:"edge_mode,omitempty"`
	ACMEEmail       string            `json:"acme_email,omitempty"`
	DNSProvider     string            `json:"dns_provider,omitempty"`
	DNSEnvName      string            `json:"dns_env_name,omitempty"`
	OutDir          string            `json:"out_dir,omitempty"`
	DataDir         string            `json:"data_dir,omitempty"`
	CompletedStage  string            `json:"completed_stage,omitempty"`
	StageEvidence   map[string]string `json:"stage_evidence,omitempty"`
	Blocker         string            `json:"blocker,omitempty"`
	BinaryVersion   string            `json:"binary_version,omitempty"`
	UpdatedAt       string            `json:"updated_at,omitempty"`
}

// SetupFingerprint captures every non-secret deployment-affecting input so any
// change to topology, DNS provider/env-var name, paths, Caddy version, or
// rendered template version invalidates stale resume evidence.
type SetupFingerprint struct {
	Hostname        string `json:"hostname"`
	EdgeMode        string `json:"edge_mode"`
	ACMEEmail       string `json:"acme_email"`
	DNSProvider     string `json:"dns_provider"`
	DNSEnvName      string `json:"dns_env_name"`
	OutDir          string `json:"out_dir"`
	DataDir         string `json:"data_dir"`
	CaddyVersion    string `json:"caddy_version"`
	TemplateVersion int    `json:"template_version"`
}

func computeSetupFingerprint(fp SetupFingerprint) string {
	fp.Hostname = strings.ToLower(strings.TrimSpace(fp.Hostname))
	fp.EdgeMode = strings.TrimSpace(fp.EdgeMode)
	fp.ACMEEmail = strings.TrimSpace(fp.ACMEEmail)
	fp.DNSProvider = strings.ToLower(strings.TrimSpace(fp.DNSProvider))
	fp.DNSEnvName = strings.TrimSpace(fp.DNSEnvName)
	fp.OutDir = strings.TrimSpace(fp.OutDir)
	fp.DataDir = strings.TrimSpace(fp.DataDir)
	if fp.CaddyVersion == "" {
		fp.CaddyVersion = setup.PinnedCaddyVersion
	}
	if fp.TemplateVersion == 0 {
		fp.TemplateVersion = setupTemplateVersion
	}
	raw, _ := json.Marshal(fp)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func setupFingerprint(hostname, edge, acmeEmail string) string {
	return computeSetupFingerprint(SetupFingerprint{
		Hostname:  hostname,
		EdgeMode:  edge,
		ACMEEmail: acmeEmail,
	})
}

func setupStatePath() (string, error) {
	// P1-13: privileged root setup stores system bootstrap state in system
	// state (/var/lib/ocliv/setup-state.json), NEVER writing root-owned files
	// into SUDO_USER's ~/.config/ocliv.
	if os.Geteuid() == 0 && os.Getenv("OCLIV_CONFIG_DIR") == "" {
		return filepath.Join("/var/lib/ocliv", "setup-state.json"), nil
	}
	dir, _, _, err := agentFiles()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "setup-state.json"), nil
}

// checkSafeUserConfigDir refuses to follow a symlinked config directory or
// target file (hardening the privileged sudo write boundary).
func checkSafeUserConfigDir(path string) error {
	dir := filepath.Dir(path)
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlinked config directory %s", dir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("config path %s is not a directory", dir)
		}
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlinked state file %s", path)
		}
	}
	return nil
}

// loadSetupStateStrict reads and validates setup-state.json, rejecting
// unsupported/newer schema versions rather than silently ignoring them (A9).
func loadSetupStateStrict() (setupState, bool, error) {
	p, err := setupStatePath()
	if err != nil {
		return setupState{}, false, err
	}
	if err := checkSafeUserConfigDir(p); err != nil {
		return setupState{}, false, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return setupState{}, false, nil
		}
		return setupState{}, false, err
	}
	var st setupState
	if err := json.Unmarshal(b, &st); err != nil {
		return setupState{}, false, fmt.Errorf("corrupt setup state %s: %w", p, err)
	}
	if st.SchemaVersion != 0 && st.SchemaVersion != setupStateSchemaVersion {
		return setupState{}, false, fmt.Errorf("unsupported setup state schema version %d at %s (supported: %d)", st.SchemaVersion, p, setupStateSchemaVersion)
	}
	return st, true, nil
}

func loadSetupState() (setupState, bool) {
	st, ok, err := loadSetupStateStrict()
	if err != nil || !ok {
		return setupState{}, false
	}
	return st, true
}

// planSetupResume computes the exact stage to resume from by validating the
// deployment fingerprint and revalidating external evidence for each completed
// stage up to st.CompletedStage (A9).
func planSetupResume(st setupState, wantFingerprint string, revalidate func(stage string) bool) (resumeStage string, revalidated []string) {
	if wantFingerprint == "" || st.Fingerprint != wantFingerprint {
		return stageDetected, nil
	}
	completedIdx := setupStageIndex(st.CompletedStage)
	if completedIdx < 0 {
		return stageDetected, nil
	}
	for i := 0; i <= completedIdx && i < len(setupStageOrder); i++ {
		stage := setupStageOrder[i]
		if stage == stageComplete {
			return stageComplete, revalidated
		}
		if revalidate != nil && !revalidate(stage) {
			return stage, revalidated
		}
		revalidated = append(revalidated, stage)
	}
	if completedIdx+1 < len(setupStageOrder) {
		return setupStageOrder[completedIdx+1], revalidated
	}
	return stageComplete, revalidated
}

func saveSetupState(st setupState) error {
	p, err := setupStatePath()
	if err != nil {
		return err
	}
	if err := checkSafeUserConfigDir(p); err != nil {
		return err
	}
	st.SchemaVersion = setupStateSchemaVersion
	st.TemplateVersion = setupTemplateVersion
	st.BinaryVersion = BinaryVersion
	if st.Fingerprint == "" {
		st.Fingerprint = computeSetupFingerprint(SetupFingerprint{
			Hostname:        st.Hostname,
			EdgeMode:        st.EdgeMode,
			ACMEEmail:       st.ACMEEmail,
			DNSProvider:     st.DNSProvider,
			DNSEnvName:      st.DNSEnvName,
			OutDir:          st.OutDir,
			DataDir:         st.DataDir,
			CaddyVersion:    setup.PinnedCaddyVersion,
			TemplateVersion: setupTemplateVersion,
		})
	}
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic0600(p, string(b)+"\n")
}

// checkpointSetup persists a completed stage with evidence, preserving all
// previously accumulated evidence (not replacing the whole map).
func checkpointSetup(st *setupState, stage string, evidence map[string]string) error {
	if st.StageEvidence == nil {
		st.StageEvidence = make(map[string]string)
	}
	for k, v := range evidence {
		st.StageEvidence[k] = v
	}
	st.CompletedStage = stage
	return saveSetupState(*st)
}

// revalidateStage returns a per-stage validator with live system checks where
// possible. DNS_VERIFIED performs an actual hostname lookup; installed/ready
// stages inspect systemd service state; artifact stages check that rendered
// files still exist on disk.
func revalidateStage(st setupState) func(string) bool {
	return func(stage string) bool {
		switch stage {
		case stageDetected:
			return st.StageEvidence[stageDetected] != ""
		case stageDNSUpdated:
			return st.StageEvidence[stageDNSUpdated] != ""
		case stageDNSVerified:
			if st.Hostname == "" || st.StageEvidence[stageDNSVerified] == "" {
				return false
			}
			// Live DNS check: verify the hostname still resolves from here.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addrs, err := setupLookupHost(ctx, st.Hostname)
			return err == nil && len(addrs) > 0
		case stageArtifactsRendered:
			artifactDir := st.OutDir
			if artifactDir == "" {
				artifactDir = st.DataDir
			}
			if st.StageEvidence[stageArtifactsRendered] == "" || artifactDir == "" {
				return false
			}
			for _, f := range []string{"Caddyfile", "relay.env", "ocliv-relay.service"} {
				if _, err := os.Stat(filepath.Join(artifactDir, f)); err != nil {
					return false
				}
			}
			return true
		case stageSystemInstalled:
			if st.StageEvidence[stageSystemInstalled] == "" {
				return false
			}
			if _, err := os.Stat("/etc/caddy/Caddyfile"); err != nil {
				return false
			}
			if _, err := os.Stat("/etc/ocliv/relay.env"); err != nil {
				return false
			}
			return exec.Command("systemctl", "is-enabled", "ocliv-relay").Run() == nil
		case stageRelayReady:
			if st.StageEvidence[stageRelayReady] == "" {
				return false
			}
			return exec.Command("systemctl", "is-active", "ocliv-relay").Run() == nil
		case stageRefreshTimerReady:
			if st.StageEvidence[stageRefreshTimerReady] == "" {
				return false
			}
			return exec.Command("systemctl", "is-active", "ocliv-dns-refresh.timer").Run() == nil
		case stageComplete:
			return st.CompletedStage == stageComplete
		default:
			return false
		}
	}
}

// stageAtOrBefore reports whether stage a is at or before stage b in the
// canonical stage order. Both stages must be valid; unknown stages return false.
func stageAtOrBefore(a, b string) bool {
	ia := setupStageIndex(a)
	ib := setupStageIndex(b)
	if ia < 0 || ib < 0 {
		return false
	}
	return ia <= ib
}

// runSuppressedStdout executes fn while capturing stdout so --json mode emits
// strictly one valid JSON document to stdout with zero human-prose prefix.
func runSuppressedStdout(fn func() int) (int, string) {
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return fn(), ""
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	rc := fn()
	_ = w.Close()
	os.Stdout = orig
	captured := <-done
	_ = r.Close()
	return rc, strings.TrimSpace(captured)
}

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
	dnsProvider := ""
	dnsEnv := ""
	compartment := ""
	zone := ""
	confirmCreate := false
	refreshDNS := false
	edge := "auto"
	edgeExplicit := false
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
		case strings.HasPrefix(a, "--dns-provider="):
			dnsProvider = strings.TrimPrefix(a, "--dns-provider=")
		case a == "--dns-provider" && i+1 < len(argv):
			i++
			dnsProvider = argv[i]
		case strings.HasPrefix(a, "--dns-env="):
			dnsEnv = strings.TrimPrefix(a, "--dns-env=")
		case a == "--dns-env" && i+1 < len(argv):
			i++
			dnsEnv = argv[i]
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
		case strings.HasPrefix(a, "--edge="):
			edge = strings.TrimPrefix(a, "--edge=")
			edgeExplicit = true
		case a == "--edge" && i+1 < len(argv):
			i++
			edge = argv[i]
			edgeExplicit = true
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
	if auto && !check && !dryRun && !refreshDNS && echoV4 == defaultEchoV4 && echoV6 == defaultEchoV6 {
		if prev, ok := loadSetupState(); ok {
			if hostname == "" && prev.Hostname != "" {
				hostname = prev.Hostname
			}
			if acmeEmail == "" && prev.ACMEEmail != "" {
				acmeEmail = prev.ACMEEmail
			}
			if !edgeExplicit && prev.EdgeMode != "" {
				edge = prev.EdgeMode
			}
			if dnsProvider == "" && prev.DNSProvider != "" {
				dnsProvider = prev.DNSProvider
			}
			if outDir == "" && prev.OutDir != "" {
				outDir = prev.OutDir
			}
		}
	}
	if auto && !check && !refreshDNS && !persistentSupervisorSupported() {
		fmt.Fprintf(os.Stderr, "error: `ocliv setup --auto` requires systemd-based Linux; native relay provisioning on %s is not yet supported\n", runtime.GOOS)
		return apperr.ExitCLIValidation
	}
	if edge != "auto" && edge != "tunnel" && edge != "single-host" && edge != "wildcard" {
		fmt.Fprintln(os.Stderr, "error: --edge must be auto, single-host, wildcard, or tunnel")
		return apperr.ExitCLIValidation
	}
	// A11: Default edge "auto" uses the single-source DefaultEdgeMode() ("wildcard").
	if edge == "auto" {
		edge = DefaultEdgeMode()
	}
	// A9: Validate persisted setup-state schema strictly before resuming.
	var resumeStage string
	prevState, hasPrev, serr := loadSetupStateStrict()
	if serr != nil {
		fmt.Fprintln(os.Stderr, "error: "+serr.Error())
		return apperr.ExitInternal
	}
	if hasPrev && !check && !dryRun && !refreshDNS {
		wantFP := computeSetupFingerprint(SetupFingerprint{
			Hostname:        hostname,
			EdgeMode:        edge,
			ACMEEmail:       acmeEmail,
			DNSProvider:     dnsProvider,
			DNSEnvName:      dnsEnv,
			OutDir:          outDir,
			DataDir:         dataDir,
			CaddyVersion:    setup.PinnedCaddyVersion,
			TemplateVersion: setupTemplateVersion,
		})
		var revalidated []string
		resumeStage, revalidated = planSetupResume(prevState, wantFP, revalidateStage(prevState))
		if len(revalidated) > 0 {
			fmt.Fprintf(os.Stderr, "setup: resuming from %s (revalidated: %s)\n",
				resumeStage, strings.Join(revalidated, ", "))
		}
	}
	// skipStage returns true when a stage was already proven in a prior run and
	// does not need to be re-executed. The resumeStage itself is the FIRST stage
	// that must run — only stages strictly before it are skipped.
	skipStage := func(stage string) bool {
		if resumeStage == "" {
			return false // fresh run: execute all stages
		}
		ri := setupStageIndex(resumeStage)
		si := setupStageIndex(stage)
		if ri < 0 || si < 0 {
			return false // unknown stage: safe default is execute
		}
		return si < ri
	}
	if dryRun && hostname == "" {
		fmt.Fprintln(os.Stderr, "--dry-run needs --hostname ZONE.dynv6.net (or ZONE.duckdns.org)")
		return apperr.ExitCLIValidation
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d := setup.Gather(ctx, echoV4, echoV6)
	// When resuming, preserve all previously accumulated evidence so that
	// checkpoints merge into the existing record rather than overwriting it.
	// Overwrite only current run's configuration inputs.
	state := prevState
	state.DetectedPath = d.Path.String()
	state.Hostname = hostname
	state.EdgeMode = edge
	state.ACMEEmail = acmeEmail
	state.DNSProvider = dnsProvider
	state.DNSEnvName = dnsEnv
	state.OutDir = outDir
	state.DataDir = dataDir
	state.TemplateVersion = setupTemplateVersion
	state.Fingerprint = computeSetupFingerprint(SetupFingerprint{
		Hostname:        hostname,
		EdgeMode:        edge,
		ACMEEmail:       acmeEmail,
		DNSProvider:     dnsProvider,
		DNSEnvName:      dnsEnv,
		OutDir:          outDir,
		DataDir:         dataDir,
		CaddyVersion:    setup.PinnedCaddyVersion,
		TemplateVersion: setupTemplateVersion,
	})
	if !check && !dryRun && !refreshDNS && echoV4 == defaultEchoV4 && echoV6 == defaultEchoV6 && !skipStage(stageDetected) {
		blocker := ""
		if hostname == "" {
			blocker = "hostname_required"
		}
		state.Blocker = blocker
		if serr := checkpointSetup(&state, stageDetected, map[string]string{stageDetected: d.Path.String()}); serr != nil {
			fmt.Fprintln(os.Stderr, "error: cannot persist setup state: "+serr.Error())
			return apperr.ExitInternal
		}
	}
	hasAction := refreshDNS || (auto && !check && (provider != "" || hostname != ""))
	if jsonOut && !hasAction {
		raw, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		fmt.Println(string(raw))
		return apperr.ExitOK
	}
	if !jsonOut {
		printSetupReport(d)
	}
	emitSetupJSON := func(action, stage, detail string, rc int) int {
		if !jsonOut {
			return rc
		}
		provisioningComplete := rc == apperr.ExitOK &&
			stage != "BLOCKED" && stage != "PLAN_ONLY" && stage != "NOT_NEEDED" &&
			stage != "dns_in_progress" && stage != "FAILED"
		payload := map[string]any{
			"ok":                    rc == apperr.ExitOK,
			"command_ok":            rc == apperr.ExitOK,
			"provisioning_complete": provisioningComplete,
			"outcome":               stage,
			"exit_code":             rc,
			"action":                action,
			"hostname":              hostname,
			"edge_mode":             edge,
			"dry_run":               dryRun,
			"completed_stage":       stage,
			"detection":             d,
		}
		if detail != "" {
			payload["detail"] = detail
		}
		raw, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		fmt.Println(string(raw))
		return rc
	}
	if refreshDNS {
		if hostname == "" {
			fmt.Fprintln(os.Stderr, "--refresh-dns needs --hostname ZONE.dynv6.net (or ZONE.duckdns.org)")
			return apperr.ExitCLIValidation
		}
		var rc int
		var detail string
		if jsonOut {
			rc, detail = runSuppressedStdout(func() int {
				return runSetupRefreshDNS(ctx, hostname, tokenFile, echoV4, echoV6)
			})
		} else {
			rc = runSetupRefreshDNS(ctx, hostname, tokenFile, echoV4, echoV6)
		}
		stage := "dns_refresh_failed"
		if rc == apperr.ExitOK {
			stage = "dns_refreshed"
		}
		return emitSetupJSON("refresh_dns", stage, detail, rc)
	}
	if check || !auto {
		return apperr.ExitOK
	}
	if provider != "" {
		var outcome, detail string
		var rc int
		if jsonOut {
			rc, detail = runSuppressedStdout(func() int {
				var pRC int
				outcome, _, pRC = runSetupProvider(ctx, d, provider, compartment, zone, confirmCreate)
				return pRC
			})
		} else {
			outcome, detail, rc = runSetupProvider(ctx, d, provider, compartment, zone, confirmCreate)
		}
		return emitSetupJSON("provider", outcome, detail, rc)
	}
	if hostname == "" {
		printSetupNext(d)
		return apperr.ExitOK
	}
	// If a prior run completed all stages and they all revalidated, there is
	// nothing to re-provision. Report existing deployment as complete.
	if !dryRun && resumeStage == stageComplete {
		fmt.Printf("setup already complete for %s; all prior stages revalidated — nothing to re-run\n", hostname)
		return emitSetupJSON("setup_dns", stageComplete, "already complete; all stages revalidated", apperr.ExitOK)
	}
	var rc int
	var detail string
	if jsonOut {
		rc, detail = runSuppressedStdout(func() int {
			return runSetupDNS(ctx, d, hostname, tokenFile, acmeEmail, outDir, dataDir, dryRun, edge, dnsProvider, dnsEnv, &state, skipStage)
		})
	} else {
		rc = runSetupDNS(ctx, d, hostname, tokenFile, acmeEmail, outDir, dataDir, dryRun, edge, dnsProvider, dnsEnv, &state, skipStage)
	}
	stage := state.CompletedStage
	if stage == "" {
		stage = "dns_in_progress"
	}
	if rc == apperr.ExitOK {
		if dryRun {
			stage = "dry_run_ok"
		} else if acmeEmail != "" {
			stage = stageComplete // canonical stage name so planSetupResume can index it
		}
	}
	if !dryRun && rc == apperr.ExitOK && stage == stageComplete {
		state.Blocker = ""
		state.DataDir = dataDir
		if serr := checkpointSetup(&state, stageComplete, map[string]string{
			"hostname":    hostname,
			"edge":        edge,
			stageComplete: time.Now().UTC().Format(time.RFC3339),
		}); serr != nil {
			fmt.Fprintln(os.Stderr, "error: cannot persist setup state: "+serr.Error())
			rc = apperr.ExitInternal
		}
	} else if !dryRun && rc != apperr.ExitOK {
		state.Blocker = "setup_incomplete"
		_ = saveSetupState(state)
	}
	return emitSetupJSON("setup_dns", stage, detail, rc)
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
	var changed bool
	var err error
	if setup.IsDuckDNSZone(hostname) {
		changed, err = setup.RefreshDuckDNS(ctx, duckdnsEndpoint(), hostname, token, echoV4, echoV6)
	} else {
		changed, err = setup.RefreshDynDNS(ctx, dynv6Endpoint(), hostname, token, echoV4, echoV6)
	}
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

// readSecretFileStrict reads an owner-only secret file safely using a single
// O_NOFOLLOW file descriptor (preventing symlink/TOCTOU races under sudo),
// verifying regular file type, mode 0600, approved owner UID, and bounded size.
func readSecretFileStrict(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("secret file %q must be a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file %q is group/other-readable (want 0600); fix permissions first", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		euid := uint32(os.Geteuid())
		allowed := st.Uid == euid || st.Uid == 0
		if !allowed && euid == 0 {
			if suidStr := strings.TrimSpace(os.Getenv("SUDO_UID")); suidStr != "" {
				if suid, perr := strconv.ParseUint(suidStr, 10, 32); perr == nil && st.Uid == uint32(suid) {
					allowed = true
				}
			}
		}
		if !allowed {
			return "", fmt.Errorf("token file %q owned by unexpected uid %d", path, st.Uid)
		}
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4096+1))
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 {
		return "", fmt.Errorf("token file %q exceeds 4096 byte limit", path)
	}
	return strings.TrimSpace(string(raw)), nil
}

// readDynv6Token resolves the provider credential from DYNV6_TOKEN or
// an owner-only --token-file. The token never comes from argv.
func readDynv6Token(tokenFile, hostname string) (string, int) {
	isDuck := setup.IsDuckDNSZone(hostname)
	envVar := "DYNV6_TOKEN"
	if isDuck {
		envVar = "DUCKDNS_TOKEN"
	}
	token := strings.TrimSpace(os.Getenv(envVar))
	if tokenFile != "" {
		secret, err := readSecretFileStrict(tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return "", apperr.ExitCLIValidation
		}
		token = secret
	}
	if token == "" {
		if isDuck {
			fmt.Fprintf(os.Stderr, "DuckDNS token needed for %q: copy your token from https://www.duckdns.org, then export DUCKDNS_TOKEN or pass --token-file PATH (0600)\n", hostname)
		} else {
			fmt.Fprintf(os.Stderr, "dynv6 HTTP token needed for %q: create one at https://dynv6.com/keys (HTTP token for the zone), then export DYNV6_TOKEN or pass --token-file PATH (0600)\n", hostname)
		}
		return "", apperr.ExitAuth
	}
	return token, apperr.ExitOK
}

func runSetupDNS(ctx context.Context, d setup.Detection, hostname, tokenFile, acmeEmail, outDir, dataDir string, dryRun bool, edge, dnsProvider, dnsEnv string, state *setupState, skipStage func(string) bool) int {
	token, code := readDynv6Token(tokenFile, hostname)
	if code != apperr.ExitOK {
		return code
	}
	isDuck := setup.IsDuckDNSZone(hostname)
	if dryRun {
		fmt.Printf("dns update: %s -> v4=%s v6=%s (token from %s, redacted)\n",
			hostname, nonEmpty(d.EgressV4), nonEmpty(d.EgressV6), tokenSourceForHost(tokenFile, hostname))
		fmt.Printf("dry-run: no request sent\n")
		return apperr.ExitOK
	}

	// Stage 1: DNS_UPDATED
	if skipStage != nil && skipStage(stageDNSUpdated) {
		fmt.Printf("setup: skipping %s (already verified)\n", stageDNSUpdated)
	} else {
		fmt.Printf("dns update: %s -> v4=%s v6=%s (token from %s, redacted)\n",
			hostname, nonEmpty(d.EgressV4), nonEmpty(d.EgressV6), tokenSourceForHost(tokenFile, hostname))
		var updErr error
		if isDuck {
			updErr = setup.UpdateDuckDNS(ctx, duckdnsEndpoint(), hostname, token, d.EgressV4, d.EgressV6)
		} else {
			updErr = setup.UpdateDynv6(ctx, dynv6Endpoint(), hostname, token, d.EgressV4, d.EgressV6)
		}
		if updErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", updErr)
			return apperr.ExitRelayTLS
		}
		fmt.Printf("dns updated for %s; verify with: dig +short %s A; dig +short %s AAAA\n", hostname, hostname, hostname)
		if state != nil {
			_ = checkpointSetup(state, stageDNSUpdated, map[string]string{
				stageDNSUpdated: time.Now().UTC().Format(time.RFC3339),
			})
		}
	}

	if acmeEmail == "" {
		return apperr.ExitOK
	}

	// Stage 2: DNS_VERIFIED
	if skipStage != nil && skipStage(stageDNSVerified) {
		fmt.Printf("setup: skipping %s (already verified)\n", stageDNSVerified)
	} else {
		matched, addrs, err := verifyDNSResolution(ctx, hostname, []string{d.EgressV4, d.EgressV6})
		if err != nil {
			fmt.Fprintf(os.Stderr, "dns for %s not resolving here yet (%v); wait for propagation, then re-run `ocliv relay setup --auto --hostname %s --acme-email %s`\n", hostname, err, hostname, acmeEmail)
			return apperr.ExitRelayTLS
		}
		if !matched {
			fmt.Fprintf(os.Stderr, "dns for %s resolves to %s here, not to observed egress %s/%s; refusing to proceed with an unverified endpoint (propagation delay or wrong zone?)\n",
				hostname, strings.Join(addrs, ","), nonEmpty(d.EgressV4), nonEmpty(d.EgressV6))
			return apperr.ExitRelayTLS
		}
		if edge == "tunnel" || edge == "wildcard" {
			if wmatched, _, werr := verifyWildcardDNS(ctx, hostname, []string{d.EgressV4, d.EgressV6}); werr != nil || !wmatched {
				fmt.Fprintf(os.Stderr, "ACTION REQUIRED: *.t.%s does not resolve to this host here", hostname)
				if werr != nil {
					fmt.Fprintf(os.Stderr, " (%v)", werr)
				}
				fmt.Fprintf(os.Stderr, "; tunnel hostnames like <id>.t.%s would not validate.\n", hostname)
				fmt.Fprintf(os.Stderr, "ACTION REQUIRED: create one wildcard record — *.t.%s A %s%s — then re-run `ocliv relay setup --auto --hostname %s --acme-email %s`\n",
					hostname, nonEmpty(d.EgressV4), wildcardAAAASuffix(d.EgressV6), hostname, acmeEmail)
				return apperr.ExitRelayTLS
			}
		}
		if state != nil {
			_ = checkpointSetup(state, stageDNSVerified, map[string]string{
				stageDNSVerified: strings.Join(addrs, ","),
			})
		}
	}

	// Stage 3: ARTIFACTS_RENDERED
	if outDir == "" {
		baseDir := "/var/lib/ocliv"
		if os.Geteuid() != 0 {
			dir, _, _, err := agentFiles()
			if err != nil {
				fmt.Fprintln(os.Stderr, "error: "+err.Error())
				return apperr.ExitInternal
			}
			baseDir = dir
		}
		outDir = filepath.Join(baseDir, "setup-"+strings.ToLower(hostname))
	}
	if state != nil {
		state.OutDir = outDir
	}
	if skipStage != nil && skipStage(stageArtifactsRendered) {
		fmt.Printf("setup: skipping %s (already verified in %s)\n", stageArtifactsRendered, outDir)
	} else {
		initArgv := []string{"--domain", hostname, "--edge", edge, "--acme-email", acmeEmail, "--out", outDir}
		if edge != "wildcard" {
			initArgv = append(initArgv, "--mcp-host", hostname)
		} else {
			if dnsProvider != "" {
				initArgv = append(initArgv, "--dns-provider", dnsProvider)
			}
			if dnsEnv != "" {
				initArgv = append(initArgv, "--dns-env", dnsEnv)
			}
		}
		if code := cmdRelayInit(initArgv); code != apperr.ExitOK {
			return code
		}
		if bad := checkInitDir(outDir); len(bad) > 0 {
			for _, line := range bad {
				fmt.Fprintln(os.Stderr, "init check: "+line)
			}
			return apperr.ExitInternal
		}
		if state != nil {
			_ = checkpointSetup(state, stageArtifactsRendered, map[string]string{
				stageArtifactsRendered: outDir,
			})
		}
	}

	fmt.Printf("deployment rendered to %s\n", outDir)
	code, completed := runSetupBootstrap(d, hostname, outDir, dataDir, token, dnsProvider, state, skipStage)
	if code == apperr.ExitOK && completed {
		fmt.Printf("relay provisioning complete for %s\n", hostname)
	} else {
		fmt.Printf("relay provisioning incomplete — artifacts kept in %s for inspection\n", outDir)
	}
	return code
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
func runSetupBootstrap(d setup.Detection, hostname, deployDir, dataDir, dnsToken, dnsProvider string, state *setupState, skipStage func(string) bool) (int, bool) {
	_, caddyErr := exec.LookPath("caddy")
	caddyPresent := caddyErr == nil
	caddyHasDNS := true
	if caddyPresent && dnsProvider != "" {
		caddyHasDNS = setup.CaddyHasDNSModule(dnsProvider)
	}
	env := setup.BootstrapEnv{
		AsRoot:            os.Geteuid() == 0,
		CaddyPresent:      caddyPresent,
		DNSProvider:       dnsProvider,
		CaddyHasDNSModule: caddyHasDNS,
		Path:              d.Path,
		Hostname:          hostname,
		DeployDir:         deployDir,
		DataDir:           dataDir,
	}
	self, selfErr := os.Executable()
	steps, blockReason := setup.PlanBootstrap(env)
	if blockReason != "" && len(steps) == 0 {
		fmt.Printf("ACTION REQUIRED: edge provisioning blocked: %s\n", blockReason)
		return apperr.ExitRelayTLS, false
	}
	// Record each unit's enablement/activity BEFORE setup changes it, so a
	// failed run can reverse only what it actually did (a Caddy that was
	// already running stays running; a clean host's relay gets stopped).
	preState := map[string]setup.ServiceState{
		"caddy":                   setup.CaptureServiceState("caddy"),
		"ocliv-relay":             setup.CaptureServiceState("ocliv-relay"),
		"ocliv-dns-refresh.timer": setup.CaptureServiceState("ocliv-dns-refresh.timer"),
	}
	setup.ResetStartedUnits()
	setup.MarkPreState(preState)
	allAuto := true
	for _, s := range steps {
		if !s.Auto {
			allAuto = false
			fmt.Printf("manual: %s\n  %s\n", s.Title, s.Manual)
			continue
		}
		// Skip already-proven stages when resuming.
		if skipStage != nil {
			switch s.Title {
			case "install Caddy", "create service account", "install binary", "install launcher",
				"create data directory", "install relay environment", "install Caddyfile",
				"activate and reload Caddy", "install systemd unit":
				if skipStage(stageSystemInstalled) {
					fmt.Printf("auto: %s ... skipped (stage %s already verified)\n", s.Title, stageSystemInstalled)
					continue
				}
			case "enable and start relay":
				if skipStage(stageRelayReady) {
					fmt.Printf("auto: %s ... skipped (stage %s already verified)\n", s.Title, stageRelayReady)
					continue
				}
			case "install and enable dynv6 refresh timer", "install and enable duckdns refresh timer":
				if skipStage(stageRefreshTimerReady) {
					fmt.Printf("auto: %s ... skipped (stage %s already verified)\n", s.Title, stageRefreshTimerReady)
					continue
				}
			}
		}
		fmt.Printf("auto: %s ... ", s.Title)
		var err error
		switch s.Title {
		case "install Caddy":
			err = setup.InstallCaddy(dnsProvider)
		case "create service account":
			err = setup.EnsureServiceAccount(setup.RelayUser, dataDir)
		case "install binary":
			if selfErr != nil {
				err = fmt.Errorf("cannot locate the running binary: %v", selfErr)
				break
			}
			err = setup.InstallBinaryTo(self, setup.DefaultCleanHostArtifacts.Binary)
		case "install launcher":
			err = setup.InstallLauncherTo(setup.DefaultCleanHostArtifacts.Launcher)
		case "create data directory":
			err = setup.EnsureDataDir(dataDir, setup.RelayUser)
		case "install relay environment":
			err = setup.InstallEnvTo(deployDir, setup.DefaultCleanHostArtifacts.EnvFile)
		case "install Caddyfile":
			err = setup.InstallCaddyfile(deployDir)
		case "activate and reload Caddy":
			err = setup.ActivateAndReloadCaddy()
			if err == nil {
				setup.MarkStarted("caddy")
			}
		case "install systemd unit":
			err = setup.InstallUnit(deployDir)
			if err == nil && state != nil {
				_ = checkpointSetup(state, stageSystemInstalled, map[string]string{
					stageSystemInstalled: time.Now().UTC().Format(time.RFC3339),
				})
			}
		case "enable and start relay":
			err = setup.StartRelay()
			if err == nil {
				setup.MarkStarted("ocliv-relay")
				if state != nil {
					_ = checkpointSetup(state, stageRelayReady, map[string]string{
						stageRelayReady: time.Now().UTC().Format(time.RFC3339),
					})
				}
			}
		case "install and enable dynv6 refresh timer", "install and enable duckdns refresh timer":
			err = setup.InstallDNSRefresh(hostname, dnsToken, dataDir)
			if err == nil {
				err = setup.EnableDynv6RefreshTimer()
				before := preState["ocliv-dns-refresh.timer"]
				after := setup.CaptureServiceState("ocliv-dns-refresh.timer")
				if before.Enabled != after.Enabled || before.Active != after.Active {
					setup.MarkStarted("ocliv-dns-refresh.timer")
				}
				if err == nil && state != nil {
					_ = checkpointSetup(state, stageRefreshTimerReady, map[string]string{
						stageRefreshTimerReady: time.Now().UTC().Format(time.RFC3339),
					})
				}
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
			// failures are reported, never silently ignored. The
			// binary and data directory roll back beside the
			// managed files: a clean host whose env step failed
			// must not keep a launcher-less binary behind.
			// Service transitions this run actually performed are
			// reversed FIRST (stop a relay we started, disable a
			// unit we enabled) so a data dir the relay just
			// populated can still be inspected/removed; a service
			// that was already running/enabled before setup is
			// never touched.
			rollbackFailed := false
			restoredAny := false
			for _, unit := range []string{"ocliv-relay", "ocliv-dns-refresh.timer", "caddy"} {
				if !setup.StartedUnits()[unit] {
					continue
				}
				if rerr := setup.RestoreService(unit); rerr != nil {
					fmt.Printf("rollback FAILED for service %s: %v\n", unit, rerr)
					rollbackFailed = true
				} else {
					fmt.Printf("rolled back service %s to its pre-setup state\n", unit)
				}
			}
			for _, dst := range setupManagedDestinations {
				restored, rerr := setup.RollbackInstalled(dst)
				if rerr != nil {
					fmt.Printf("rollback FAILED for %s: %v\n", dst, rerr)
					rollbackFailed = true
				}
				restoredAny = restoredAny || restored
			}
			if rerr := setup.RollbackDNSRefreshToken(hostname, dataDir); rerr != nil {
				fmt.Printf("rollback FAILED for DNS refresh token in %s: %v\n", dataDir, rerr)
				rollbackFailed = true
			}
			restored, rerr := setup.RollbackBinary(setup.DefaultCleanHostArtifacts.Binary)
			if rerr != nil {
				fmt.Printf("rollback FAILED for binary %s: %v\n", setup.DefaultCleanHostArtifacts.Binary, rerr)
				rollbackFailed = true
			}
			restoredAny = restoredAny || restored
			restored, rerr = setup.RollbackDataDir(dataDir)
			if rerr != nil {
				fmt.Printf("rollback FAILED for data dir %s: %v\n", dataDir, rerr)
				rollbackFailed = true
			}
			restoredAny = restoredAny || restored
			if rollbackFailed {
				fmt.Printf("manual recovery: inspect backups (*.ocliv-bak) and journal (*.ocliv-new) beside the destinations above, restore by hand, then re-run\n")
			} else if restoredAny {
				// The unit install reloads the manager at install
				// time; re-read the restored files so the daemon
				// does not keep the rolled-back config in memory.
				// The Caddyfile may also have been restored under
				// a running Caddy (the activate step reloaded it):
				// re-read it there too, best effort, after the
				// files are back.
				if rerr := setup.ReloadServiceManager(); rerr != nil {
					fmt.Printf("warning: service-manager reload after rollback failed: %v\n", rerr)
				}
				if rerr := setup.ReloadCaddy(); rerr != nil {
					fmt.Printf("warning: caddy reload after rollback failed (the restored Caddyfile is on disk; a stopped Caddy is left stopped): %v\n", rerr)
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
	_ = setup.CleanDNSRefreshTokenJournal(hostname, dataDir)
	fmt.Printf("verify externally: from another network, curl -v https://%s/v1/agent/challenge (no -k)\n", hostname)
	fmt.Printf("to add publishers: on each publisher machine, run `ocliv pair https://%s`, then approve here with `ocliv relay approve <CODE> --tenant <TENANT>`\n", hostname)
	return apperr.ExitOK, true
}

// runSetupProvider handles the provider-relay path for hosts with no
// direct inbound route. With a viable local path the provider is
// unnecessary, so it says so and stops. Otherwise it checks the
// operator's own cloud tooling, prints the free-tier plan, and creates
// only with explicit --confirm-create plus compartment and zone.
// runSetupProvider handles the provider-relay path and returns a typed outcome
// (NOT_NEEDED, BLOCKED, PLAN_ONLY, LAUNCH_REQUESTED, FAILED) so --json mode
// never infers "PROVISIONED" from a zero exit code.
func runSetupProvider(ctx context.Context, d setup.Detection, provider, compartment, zone string, confirm bool) (string, string, int) {
	if provider != "oracle" {
		msg := fmt.Sprintf("unknown provider %q (supported: oracle)", provider)
		fmt.Fprintln(os.Stderr, msg)
		return "FAILED", msg, apperr.ExitCLIValidation
	}
	if d.Path == setup.PathDirectV6 || d.Path == setup.PathDirectV4 || d.Path == setup.PathNATV4 {
		msg := fmt.Sprintf("local path is %s: self-hosting directly is simpler and free — omit --provider to bootstrap here", d.Path)
		fmt.Println(msg)
		return "NOT_NEEDED", msg, apperr.ExitOK
	}
	a := setup.OracleAdapter{Compartment: compartment, Zone: zone}
	msg, ok := a.Check(ctx)
	fmt.Println(msg)
	if !ok {
		return "BLOCKED", msg, apperr.ExitOK
	}
	fmt.Println(a.Plan())
	if err := a.Create(ctx, confirm); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		if !confirm {
			return "PLAN_ONLY", err.Error(), apperr.ExitOK
		}
		return "FAILED", err.Error(), apperr.ExitInternal
	}
	detail := "instance launch requested; continue in the OCI console, then point DNS at its public IP and re-run setup without --provider"
	fmt.Println(detail)
	return "LAUNCH_REQUESTED", detail, apperr.ExitOK
}

func tokenSourceForHost(tokenFile, hostname string) string {
	if tokenFile != "" {
		return "--token-file"
	}
	if setup.IsDuckDNSZone(hostname) {
		return "DUCKDNS_TOKEN"
	}
	return "DYNV6_TOKEN"
}

// Unexported test-only injection hooks; production binaries NEVER honor
// ambient environment overrides for credential-bearing DNS update endpoints.
var (
	dynv6EndpointTestOverride   string
	duckdnsEndpointTestOverride string
)

func dynv6Endpoint() string {
	if dynv6EndpointTestOverride != "" {
		return dynv6EndpointTestOverride
	}
	return setup.Dynv6UpdateEndpoint
}

func duckdnsEndpoint() string {
	if duckdnsEndpointTestOverride != "" {
		return duckdnsEndpointTestOverride
	}
	return setup.DuckDNSUpdateEndpoint
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

func recommendedEdgeMode(d setup.Detection) string {
	_ = d
	return DefaultEdgeMode()
}

func printSetupReport(d setup.Detection) {
	fmt.Printf("path: %s\n", d.Path)
	fmt.Printf("recommended edge: %s\n", recommendedEdgeMode(d))
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
		fmt.Printf("- Allow TCP 443 inbound in the host firewall; this host can serve directly (relay stays on 127.0.0.1, Caddy terminates TLS).\n")
		fmt.Printf("- The default `--edge wildcard` issues one wildcard certificate via DNS-01 (pass `--dns-provider NAME`, no per-lease ACME). Use `--edge single-host` if you only need single-host path routes without wildcard DNS, or `--edge tunnel` for noncanonical on-demand lab mode.\n")
		fmt.Printf("- Re-run `ocliv relay setup --auto` once DNS resolves here; setup resumes from the stored non-secret setup state.\n")
	case setup.PathNATV4:
		fmt.Printf("- In the router admin page, forward TCP 443 to this host (%s).\n", firstOr(d.LocalV4, "its LAN address"))
		fmt.Printf("- The default `--edge wildcard` uses DNS-01 on 443 (no TCP 80 required); `--edge single-host` also uses 443 alone (TLS-ALPN-01). Only the noncanonical `--edge tunnel` lab mode needs TCP 80.\n")
		fmt.Printf("- Pick a DNS name pointing at the router's public IPv4; keep it updated if the address changes.\n")
		fmt.Printf("- Re-run `ocliv relay setup --auto` after the forward is in place.\n")
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
