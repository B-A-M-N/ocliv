package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/config"
)

// HostTransactionResult is the machine-readable verdict for `ocliv host --json`.
// It separates configured, running, persistence-configured, reboot-proven,
// publicly-serving, and externally-verified states so automation never mistakes
// a partial setup for a verified host.
type HostTransactionResult struct {
	Service               string                  `json:"service"`
	ServiceID             string                  `json:"service_id,omitempty"`
	Type                  string                  `json:"type"`
	Local                 string                  `json:"local,omitempty"`
	StdioCmd              []string                `json:"stdio_cmd,omitempty"`
	Public                string                  `json:"public,omitempty"`
	PublicationID         string                  `json:"publication_id,omitempty"`
	Authentication        string                  `json:"authentication"`
	TrustedClients        []string                `json:"trusted_clients,omitempty"`
	Configured            bool                    `json:"configured"`
	RunningNow            bool                    `json:"running_now"`
	PersistenceConfigured bool                    `json:"persistence_configured"`
	RebootRecoveryProven  bool                    `json:"reboot_recovery_proven"`
	PubliclyServing       bool                    `json:"publicly_serving"`
	PubliclyVerified      bool                    `json:"publicly_verified"`
	State                 string                  `json:"state"`
	Health                string                  `json:"health"`
	VerificationLevel     string                  `json:"verification_level,omitempty"`
	Layers                *ServiceLayers          `json:"layers,omitempty"`
	Persistence           PersistenceVerification `json:"persistence"`
	Error                 string                  `json:"error,omitempty"`
	RecoveryAction        string                  `json:"recovery_action,omitempty"`
}

func humanAuthLabel(svcType, auth string) string {
	switch auth {
	case "ocliv-managed":
		return "managed OAuth"
	case "upstream-oauth":
		return "upstream OAuth"
	case "protected":
		return "protected (share link)"
	case "public":
		return "public (unauthenticated)"
	default:
		if svcType == "http" {
			return "protected (share link)"
		}
		return auth
	}
}

func hasJSONFlag(argv []string) bool {
	for _, a := range argv {
		if a == "--" {
			break
		}
		if a == "--json" {
			return true
		}
	}
	return false
}

// cmdHost is the single-command persistent hosting orchestrator:
//
//	ocliv host PORT [--name N] [--type mcp|http] [--auth MODE] [--json]
//	ocliv host --stdio --name N [--json] -- COMMAND [ARGS...]
//
// In `--json` mode, stdout contains strictly one standalone JSON object for
// both success and failure, and all human diagnostics go to stderr.
func cmdHost(argv []string) int {
	return cmdHostWithOps(argv, defaultServiceOps())
}

// persistentSupervisorSupported reports whether this OS has native persistent
// hosting supervisor support (currently Linux with systemd).
func persistentSupervisorSupported() bool {
	return runtime.GOOS == "linux"
}

func cmdHostWithOps(argv []string, ops serviceOps) int {
	jsonOut := hasJSONFlag(argv)
	failValidation := func(msg string) int {
		if jsonOut {
			emitHostJSON(HostTransactionResult{
				State:  ServiceStateUnknown,
				Health: HealthFailed,
				Error:  msg,
			})
		} else {
			fmt.Fprintln(os.Stderr, msg)
		}
		return apperr.ExitCLIValidation
	}

	if len(argv) == 0 {
		return failValidation("usage: ocliv host [http|mcp] PORT [--name N] [--type http|mcp] [--auth MODE] [--json] | ocliv host --stdio --name N [--json] -- COMMAND...")
	}

	var port int
	var stdio, allowRoot bool
	var name, svcType, auth, profileFlag string
	var trustPresets []string
	var cmd []string

	i := 0
	if argv[0] == "http" || argv[0] == "mcp" {
		svcType = argv[0]
		i = 1
	}
	if i < len(argv) && !strings.HasPrefix(argv[i], "-") {
		p, err := strconv.Atoi(argv[i])
		if err != nil || p < 1 || p > 65535 {
			return failValidation(fmt.Sprintf("invalid port %q (want 1-65535)", argv[i]))
		}
		port = p
		i++
	}
	for ; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			cmd = argv[i+1:]
			break
		}
		switch {
		case a == "--stdio":
			stdio = true
		case a == "--json":
			jsonOut = true
		case a == "--allow-root":
			allowRoot = true
		case a == "--profile" || strings.HasPrefix(a, "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return failValidation("missing value for --profile")
			}
			profileFlag = v
		case a == "--name" || strings.HasPrefix(a, "--name="):
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				return failValidation("missing value for --name")
			}
			name = v
		case a == "--type" || strings.HasPrefix(a, "--type="):
			v, ok := mcpFlagValue(argv, &i, "type")
			if !ok {
				return failValidation("missing value for --type")
			}
			svcType = v
		case a == "--auth" || strings.HasPrefix(a, "--auth="):
			v, ok := mcpFlagValue(argv, &i, "auth")
			if !ok {
				return failValidation("missing value for --auth")
			}
			auth = v
		case a == "--trust" || strings.HasPrefix(a, "--trust="):
			v, ok := mcpFlagValue(argv, &i, "trust")
			if !ok {
				return failValidation("missing value for --trust")
			}
			if _, ok := authz.LookupTrustPreset(v); !ok {
				return failValidation(fmt.Sprintf("unknown --trust preset %q (available: chatgpt)", v))
			}
			trustPresets = append(trustPresets, strings.ToLower(strings.TrimSpace(v)))
		default:
			return failValidation(fmt.Sprintf("unknown flag %q", a))
		}
	}
	if !persistentSupervisorSupported() {
		return failValidation("persistent hosting currently requires Linux with systemd; native persistence for " + runtime.GOOS + " is not yet supported")
	}
	if os.Geteuid() == 0 && !allowRoot {
		return failValidation("refusing to run user-level `ocliv host` as root (run as your normal user, or pass --allow-root)")
	}
	if profileFlag != "" {
		prevProf := os.Getenv("OCLIV_PROFILE")
		_ = os.Setenv("OCLIV_PROFILE", profileFlag)
		defer func() {
			if prevProf == "" {
				_ = os.Unsetenv("OCLIV_PROFILE")
			} else {
				_ = os.Setenv("OCLIV_PROFILE", prevProf)
			}
		}()
	}
	if svcType == "" {
		if stdio {
			svcType = "mcp"
		} else {
			svcType = "http"
		}
	}
	if !stdio && port == 0 {
		return failValidation("usage: ocliv host [http|mcp] PORT [--name N] [--type http|mcp] [--auth MODE] [--json] | ocliv host --stdio --name N [--json] -- COMMAND...")
	}
	if stdio && len(cmd) == 0 {
		return failValidation("ocliv host --stdio requires -- COMMAND [ARGS...]")
	}
	if name == "" {
		if stdio {
			return failValidation("ocliv host --stdio requires --name N")
		}
		if svcType == "http" {
			name = fmt.Sprintf("http-%d", port)
		} else {
			name = fmt.Sprintf("mcp-%d", port)
		}
	}
	localURL := ""
	if !stdio {
		if svcType == "http" {
			localURL = fmt.Sprintf("http://127.0.0.1:%d", port)
		} else {
			localURL = fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
		}
	}
	addReq := serviceAddRequest{
		Name:        name,
		Type:        svcType,
		BackendMode: config.BackendAttached,
		LocalURL:    localURL,
		StdioCmd:    cmd,
		Auth:        auth,
	}
	if verr := validateServiceAddRequest(&addReq); verr != nil {
		return failValidation(verr.Error())
	}
	auth = addReq.Auth
	svcType = addReq.Type
	if len(trustPresets) > 0 && (svcType != "mcp" || auth != "ocliv-managed") {
		return failValidation("--trust is only supported for managed-OAuth MCP services (`ocliv host mcp PORT --trust chatgpt`)")
	}

	profile := config.ActiveProfile()
	k, keyID, err := loadKeyForProfile(profile)
	if err != nil {
		if jsonOut {
			emitHostJSON(HostTransactionResult{
				Service:        name,
				Type:           svcType,
				Authentication: auth,
				State:          ServiceStateUnknown,
				Health:         HealthBlocked,
				Error:          fmt.Sprintf("not enrolled in profile %q", profile),
				RecoveryAction: "run `ocliv device add user@this-host` on your relay, or `ocliv pair https://YOUR_RELAY` here",
			})
		} else {
			fmt.Fprintf(os.Stderr, "not enrolled in profile %q.\n", profile)
			fmt.Fprintln(os.Stderr, "Run `ocliv device add user@this-host` on your relay, or `ocliv pair https://YOUR_RELAY` on this machine first.")
		}
		return apperr.ExitAuth
	}

	res := HostTransactionResult{
		Service:        name,
		Type:           svcType,
		Local:          localURL,
		StdioCmd:       cmd,
		Authentication: auth,
		State:          ServiceStateConfigured,
		Health:         HealthUnknown,
	}

	store, err := openServicesForProfile(profile)
	if err != nil {
		res.Error = err.Error()
		res.Health = HealthFailed
		emitHostResult(res, jsonOut)
		return apperr.ExitInternal
	}

	// Step 1: Commit or safely retry local service registration (zero stdout).
	existing, exists, err := store.Get(name)
	if err != nil {
		res.Error = err.Error()
		res.Health = HealthFailed
		emitHostResult(res, jsonOut)
		return apperr.ExitInternal
	}
	if exists {
		if existing.Type != svcType {
			res.Error = fmt.Sprintf("service %q already exists with type %q (cannot switch to %q in place)", name, existing.Type, svcType)
			res.Health = HealthBlocked
			res.RecoveryAction = fmt.Sprintf("choose a new --name or remove %q explicitly", name)
			emitHostResult(res, jsonOut)
			return apperr.ExitCLIValidation
		}
		if existing.Auth != auth {
			res.Error = fmt.Sprintf("service %q already exists with auth %q (changing to %q requires explicit migration or a new publication)", name, existing.Auth, auth)
			res.Health = HealthBlocked
			res.RecoveryAction = fmt.Sprintf("choose a new --name or remove %q explicitly", name)
			emitHostResult(res, jsonOut)
			return apperr.ExitCLIValidation
		}
		relayURL := existing.RelayURL
		if relayURL == "" {
			relayURL = agentRelayURLForProfile(profile)
		}
		if oerr := verifyServiceIdentityOwnership(existing, keyID, relayURL); oerr != nil {
			res.Error = oerr.Error()
			res.Health = HealthBlocked
			emitHostResult(res, jsonOut)
			return apperr.ExitAuth
		}
		// Safely update mutable local target while preserving permanent identity,
		// bumping ConfigGeneration when the target actually changed so startHostedService
		// performs a controlled rebind/restart instead of a no-op start.
		if _, uerr := store.UpdateCAS(name, existing.Revision, func(r *config.ServiceRecord) error {
			changed := false
			if stdio {
				if strings.Join(r.StdioCmd, "\x00") != strings.Join(cmd, "\x00") || r.LocalURL != "" {
					r.StdioCmd = cmd
					r.LocalURL = ""
					changed = true
				}
			} else {
				if r.LocalURL != localURL || len(r.StdioCmd) > 0 {
					r.LocalURL = localURL
					r.StdioCmd = nil
					changed = true
				}
			}
			if changed {
				if r.ConfigGeneration <= 0 {
					r.ConfigGeneration = 1
				}
				r.ConfigGeneration++
			}
			return nil
		}); uerr != nil {
			res.Error = uerr.Error()
			res.Health = HealthFailed
			emitHostResult(res, jsonOut)
			return apperr.ExitInternal
		}
	} else {
		_, _, code, rerr := registerHostedService(serviceAddRequest{
			Name:        name,
			Type:        svcType,
			BackendMode: config.BackendAttached,
			LocalURL:    localURL,
			StdioCmd:    cmd,
			Auth:        auth,
			Profile:     profile,
		}, ops)
		if rerr != nil {
			res.Error = rerr.Error()
			res.Health = HealthFailed
			emitHostResult(res, jsonOut)
			return code
		}
	}
	res.Configured = true

	// Step 2: Start with strict readiness AND mandatory persistence configuration (zero stdout).
	_, startCode, startErr := startHostedService(serviceStartRequest{
		Name:               name,
		WaitReady:          true,
		RequirePersistence: true,
	}, ops)

	// Step 3: Collect authoritative post-start status and persistence configuration proof.
	rec, ok, _ := store.Get(name)
	if ok {
		if rec.Identity != nil {
			res.ServiceID = rec.Identity.ServiceID
		}
		res.PublicationID = rec.PublicationID
		res.Public = rec.PublicURL
		rep := inspectServiceStatus(rec, k, keyID, ops)
		pv := verifyRebootPersistence(rec, ops)
		res.State = rep.State
		res.Health = rep.Health
		res.VerificationLevel = rep.VerificationLevel
		layersCopy := rep.Layers
		res.Layers = &layersCopy
		res.Persistence = pv
		res.RunningNow = rep.ProcessState == "active"
		res.PersistenceConfigured = pv.PersistenceConfigured
		res.RebootRecoveryProven = pv.RebootRecoveryProven
		res.PubliclyServing = rep.State == ServiceStateServing && rep.PublicURL != ""
		res.PubliclyVerified = rep.PublicVerified
		if rep.PublicationID != "" {
			res.PublicationID = rep.PublicationID
		}
		if rep.PublicURL != "" {
			res.Public = rep.PublicURL
		}
		if startErr != nil {
			res.Error = startErr.Error()
		} else if rec.LastFailure != "" {
			res.Error = rec.LastFailure
		} else if !pv.PersistenceConfigured && pv.FailureReason != "" {
			res.Error = pv.FailureReason
		} else if rep.IngressDetail != "" && rep.State != ServiceStateServing {
			res.Error = rep.IngressDetail
		}
		res.RecoveryAction = rec.LastRecoveryAction
	}

	// Enforce the full transactional host contract:
	// configured + running + persistence configured + publicly serving with recorded URL.
	hostSucceeded := startCode == apperr.ExitOK &&
		res.Configured &&
		res.RunningNow &&
		res.PersistenceConfigured &&
		res.State == ServiceStateServing &&
		res.Public != ""

	if !hostSucceeded {
		if res.Error == "" {
			res.Error = fmt.Sprintf("host did not reach serving state (state=%s, persistence_configured=%v)", res.State, res.PersistenceConfigured)
		}
		if res.RecoveryAction == "" {
			res.RecoveryAction = fmt.Sprintf("fix the error above and re-run `ocliv host` with --name %s (safe to retry)", name)
		}
		emitHostResult(res, jsonOut)
		if startCode != apperr.ExitOK {
			return startCode
		}
		return apperr.ExitInternal
	}

	// Step 4: Apply any requested route-scoped client trust policies (e.g. --trust chatgpt).
	if len(trustPresets) > 0 && res.PublicationID != "" {
		relayURL := ""
		if ok && rec.RelayURL != "" {
			relayURL = rec.RelayURL
		}
		if relayURL == "" {
			relayURL = agentRelayURLForProfile(profile)
		}
		for _, preset := range trustPresets {
			pol, _, pcode, perr := applyTrustPolicyToRoute(relayURL, k, keyID, res.PublicationID, preset, nil, ops)
			if perr != nil {
				res.Error = fmt.Sprintf("service is serving, but applying --trust %s failed: %v", preset, perr)
				res.RecoveryAction = fmt.Sprintf("run `ocliv trust %s %s` to retry", name, preset)
				emitHostResult(res, jsonOut)
				return pcode
			}
			res.TrustedClients = append(res.TrustedClients, pol.DisplayLabel())
		}
	}

	emitHostResult(res, jsonOut)
	if !jsonOut && svcType == "mcp" && res.Public != "" {
		snippet, _ := json.MarshalIndent(map[string]any{
			"mcpServers": map[string]any{
				name: map[string]any{
					"url": res.Public,
				},
			},
		}, "", "  ")
		fmt.Printf("\nClaude Desktop / Cursor snippet:\n%s\n", string(snippet))
	}
	return apperr.ExitOK
}

func emitHostJSON(res HostTransactionResult) {
	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
}

func emitHostResult(res HostTransactionResult, jsonOut bool) {
	if jsonOut {
		emitHostJSON(res)
		return
	}
	fmt.Printf("\nService: %s\n", res.Service)
	if res.Local != "" {
		fmt.Printf("Local:   %s\n", res.Local)
	} else if len(res.StdioCmd) > 0 {
		fmt.Printf("Local:   stdio (%s)\n", strings.Join(res.StdioCmd, " "))
	}
	if res.Public != "" {
		fmt.Printf("Public:  %s\n", res.Public)
	} else {
		fmt.Printf("Public:  (not allocated)\n")
	}
	fmt.Println()
	persistStr := "not configured"
	if res.PersistenceConfigured {
		persistStr = "configured"
	}
	rebootStr := "not yet tested"
	if res.RebootRecoveryProven {
		rebootStr = "verified"
	}
	connStr := "disconnected"
	if res.Layers != nil && res.Layers.Agent == "connected" {
		connStr = "connected"
	}
	routeStr := strings.ToLower(res.State)
	if res.PubliclyServing {
		routeStr = "active"
	}
	fmt.Printf("Persistence:     %s\n", persistStr)
	fmt.Printf("Reboot recovery: %s\n", rebootStr)
	fmt.Printf("Connection:      %s\n", connStr)
	fmt.Printf("Route:           %s\n", routeStr)
	fmt.Printf("Authentication:  %s\n", humanAuthLabel(res.Type, res.Authentication))
	if len(res.TrustedClients) > 0 {
		fmt.Printf("Trusted clients: %s\n", strings.Join(res.TrustedClients, ", "))
	}
	if res.VerificationLevel != "" {
		fmt.Printf("Verification:    %s (publicly_verified=%v)\n", res.VerificationLevel, res.PubliclyVerified)
	}
	fmt.Println()
	if res.Error != "" {
		fmt.Fprintf(os.Stderr, "Incomplete: %s\n", res.Error)
		if res.RecoveryAction != "" {
			fmt.Fprintf(os.Stderr, "Next: %s\n", res.RecoveryAction)
		}
		return
	}
	if res.PubliclyServing && res.PersistenceConfigured {
		fmt.Println("Ready.")
	}
}
