package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
)

// Authoritative service lifecycle states (Section 6).
const (
	ServiceStateConfigured = "CONFIGURED"
	ServiceStateDisabled   = "DISABLED"
	ServiceStateStarting   = "STARTING"
	ServiceStateServing    = "SERVING"
	ServiceStateStopping   = "STOPPING"
	ServiceStateOffline    = "OFFLINE"
	ServiceStateFaulted    = "FAULTED"
	ServiceStateUnknown    = "UNKNOWN"
	ServiceStateRevoked    = "REVOKED"
)

// Authoritative health verdicts (Section 10).
const (
	HealthReady    = "READY"
	HealthDegraded = "DEGRADED"
	HealthUnknown  = "UNKNOWN"
	HealthBlocked  = "BLOCKED"
	HealthFailed   = "FAILED"
)

type serviceStopResult struct {
	Name          string `json:"name"`
	Stopped       bool   `json:"stopped"`
	State         string `json:"state"`
	PublicationID string `json:"publication_id,omitempty"`
	RetainedURL   string `json:"retained_url,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// serviceOps isolates external interactions (systemd --user, relay mgmt, probes)
// so both production and hermetic unit/integration tests use the same logic.
type serviceOps struct {
	systemctl func(args ...string) (string, error)
	mgmtCall  func(relayURL string, k *identity.KeyPair, keyID, method, path string) (int, []byte, error)
	probeLoc  func(target string, timeout time.Duration) error
	probePub  func(publicURL string, timeout time.Duration) (int, error)
	provision func(rec config.ServiceRecord, ops serviceOps) error
}

func defaultServiceOps() serviceOps {
	return serviceOps{
		systemctl: func(args ...string) (string, error) {
			uargs := append([]string{"--user"}, args...)
			out, err := exec.Command("systemctl", uargs...).CombinedOutput()
			return strings.TrimSpace(string(out)), err
		},
		mgmtCall:  mgmtCall,
		probeLoc:  agent.ProbeLocal,
		provision: provisionUserSupervisor,
		probePub: func(publicURL string, timeout time.Duration) (int, error) {
			c, err := mgmtHTTPClient(timeout)
			if err != nil {
				return 0, err
			}
			defer c.CloseIdleConnections()
			req, err := http.NewRequest(http.MethodPost, publicURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
			if err != nil {
				return 0, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			resp, err := c.Do(req)
			if err != nil {
				return 0, err
			}
			resp.Body.Close()
			return resp.StatusCode, nil
		},
	}
}

func cmdService(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service add|update|start|stop|disable|restart|status|list|remove ...")
		return apperr.ExitCLIValidation
	}
	ops := defaultServiceOps()
	switch argv[0] {
	case "add":
		return cmdServiceAdd(argv[1:], ops)
	case "update":
		return cmdServiceUpdate(argv[1:])
	case "start":
		return cmdServiceStart(argv[1:], ops)
	case "stop":
		return cmdServiceStop(argv[1:], ops)
	case "disable":
		return cmdServiceDisable(argv[1:], ops)
	case "restart":
		return cmdServiceRestart(argv[1:], ops)
	case "status":
		return cmdServiceStatus(argv[1:], ops)
	case "list":
		return cmdServiceList(argv[1:], ops)
	case "remove":
		return cmdServiceRemove(argv[1:], ops)
	case "pending":
		return cmdServicePending(argv[1:], ops)
	case "approve":
		return cmdServiceApprove(argv[1:], ops)
	case "run-publisher":
		return cmdServiceRunPublisher(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown service command %q\n", argv[0])
		return apperr.ExitCLIValidation
	}
}

func openServicesForProfile(profile string) (*config.ServiceStore, error) {
	dir, err := config.DataDirForProfile(profile)
	if err != nil {
		return nil, err
	}
	return config.OpenServiceStore(dir), nil
}

func openServices() (*config.ServiceStore, error) {
	return openServicesForProfile(config.ActiveProfile())
}

func cmdServiceAdd(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service add NAME [--type mcp|http] (--attach URL | --local URL | --manage --local URL --exec BIN | --stdio -- CMD...) [--auth MODE] [--relay URL]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	if err := config.ValidateServiceName(name); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitCLIValidation
	}
	var svcType, localURL, auth, relayURL, unit, execBin string
	var manage, stdio bool
	var stdioCmd, execArgs []string
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			if manage {
				execArgs = argv[i+1:]
			} else {
				stdioCmd = argv[i+1:]
			}
			i = len(argv)
		case a == "--stdio":
			stdio = true
		case a == "--manage":
			manage = true
		case a == "--type" || strings.HasPrefix(a, "--type="):
			v, ok := mcpFlagValue(argv, &i, "type")
			if !ok {
				return apperr.ExitCLIValidation
			}
			svcType = v
		case a == "--local" || strings.HasPrefix(a, "--local="):
			v, ok := mcpFlagValue(argv, &i, "local")
			if !ok {
				return apperr.ExitCLIValidation
			}
			localURL = v
		case a == "--attach" || strings.HasPrefix(a, "--attach="):
			v, ok := mcpFlagValue(argv, &i, "attach")
			if !ok {
				return apperr.ExitCLIValidation
			}
			localURL = v
		case a == "--exec" || strings.HasPrefix(a, "--exec="):
			v, ok := mcpFlagValue(argv, &i, "exec")
			if !ok {
				return apperr.ExitCLIValidation
			}
			execBin = v
		case a == "--auth" || strings.HasPrefix(a, "--auth="):
			v, ok := mcpFlagValue(argv, &i, "auth")
			if !ok {
				return apperr.ExitCLIValidation
			}
			auth = v
		case a == "--relay" || strings.HasPrefix(a, "--relay="):
			v, ok := mcpFlagValue(argv, &i, "relay")
			if !ok {
				return apperr.ExitCLIValidation
			}
			relayURL = v
		case a == "--unit" || strings.HasPrefix(a, "--unit="):
			v, ok := mcpFlagValue(argv, &i, "unit")
			if !ok {
				return apperr.ExitCLIValidation
			}
			unit = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	if svcType == "" {
		svcType = "mcp"
	}
	if svcType != "mcp" && svcType != "http" {
		fmt.Fprintf(os.Stderr, "invalid --type %q (want mcp or http)\n", svcType)
		return apperr.ExitCLIValidation
	}
	backendMode := config.BackendAttached
	if manage {
		backendMode = config.BackendManaged
		if execBin == "" {
			fmt.Fprintln(os.Stderr, "--manage requires --exec BIN")
			return apperr.ExitCLIValidation
		}
		if localURL == "" {
			fmt.Fprintln(os.Stderr, "--manage requires --local URL")
			return apperr.ExitCLIValidation
		}
	}
	if stdio {
		if svcType != "mcp" || len(stdioCmd) == 0 {
			fmt.Fprintln(os.Stderr, "--stdio requires --type mcp and -- COMMAND [ARGS...]")
			return apperr.ExitCLIValidation
		}
		if auth == "" {
			auth = "ocliv-managed"
		}
		if auth != "ocliv-managed" {
			fmt.Fprintln(os.Stderr, "--stdio requires --auth ocliv-managed")
			return apperr.ExitCLIValidation
		}
	} else {
		if localURL == "" {
			fmt.Fprintln(os.Stderr, "--attach/--local URL or --stdio is required")
			return apperr.ExitCLIValidation
		}
		if err := config.ValidateServiceLocalURL(localURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitCLIValidation
		}
	}
	if svcType == "mcp" {
		if auth == "" {
			auth = "ocliv-managed"
		}
		if auth != "ocliv-managed" && auth != "upstream-oauth" {
			fmt.Fprintf(os.Stderr, "invalid MCP --auth %q (want ocliv-managed or upstream-oauth)\n", auth)
			return apperr.ExitCLIValidation
		}
	} else {
		if auth == "" {
			auth = "protected"
		}
		if auth != "protected" && auth != "public" {
			fmt.Fprintf(os.Stderr, "invalid HTTP --auth %q (want protected or public)\n", auth)
			return apperr.ExitCLIValidation
		}
	}
	prof := config.ActiveProfile()
	if relayURL != "" {
		if _, err := validateRelayTarget(relayURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitCLIValidation
		}
	} else {
		relayURL = agentRelayURLForProfile(prof)
	}
	store, err := openServicesForProfile(prof)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	if _, exists, err := store.Get(name); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	} else if exists {
		fmt.Fprintf(os.Stderr, "service %q already exists (use `ocliv service update %s`)\n", name, name)
		return apperr.ExitCLIValidation
	}
	if unit == "" {
		unit = "ocliv-publisher@" + name + ".service"
	}
	backendUnit := ""
	if backendMode == config.BackendManaged {
		backendUnit = "ocliv-backend@" + name + ".service"
	}
	rec := config.ServiceRecord{
		Name:         name,
		Type:         svcType,
		BackendMode:  backendMode,
		BackendExec:  execBin,
		BackendArgs:  execArgs,
		LocalURL:     localURL,
		StdioCmd:     stdioCmd,
		Auth:         auth,
		RelayURL:     relayURL,
		Profile:      prof,
		DesiredState: config.DesiredConfigured,
		SystemdUnit:  unit,
		BackendUnit:  backendUnit,
	}
	if err := store.Put(rec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	backendStatus := "not running"
	if target, _, err := localTargetFromURL(rec.LocalURL); err == nil {
		if ops.probeLoc(target, 500*time.Millisecond) == nil {
			backendStatus = "reachable"
		}
	} else if len(rec.StdioCmd) > 0 {
		backendStatus = "stdio configured"
	}
	fmt.Printf("Service %s configured (profile=%s, mode=%s).\n", rec.Name, rec.Profile, rec.BackendMode)
	fmt.Printf("Backend: %s\n", backendStatus)
	fmt.Printf("Publisher: not installed\n")
	fmt.Printf("Public URL: not yet allocated\n")
	fmt.Printf("Next: ocliv service start %s\n", rec.Name)
	return apperr.ExitOK
}

func cmdServiceUpdate(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service update NAME [--local URL] [--relay URL]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q\n", name)
		return apperr.ExitCLIValidation
	}
	var newLocal, newRelay string
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--local" || strings.HasPrefix(a, "--local="):
			v, ok := mcpFlagValue(argv, &i, "local")
			if !ok {
				return apperr.ExitCLIValidation
			}
			if err := config.ValidateServiceLocalURL(v); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return apperr.ExitCLIValidation
			}
			newLocal = v
		case a == "--relay" || strings.HasPrefix(a, "--relay="):
			v, ok := mcpFlagValue(argv, &i, "relay")
			if !ok {
				return apperr.ExitCLIValidation
			}
			if _, err := validateRelayTarget(v); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return apperr.ExitCLIValidation
			}
			newRelay = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	updated, err := store.UpdateCAS(name, rec.Revision, func(r *config.ServiceRecord) error {
		if newLocal != "" {
			r.LocalURL = newLocal
		}
		if newRelay != "" {
			r.RelayURL = newRelay
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	fmt.Printf("✓ updated service %s (local=%s; permanent identity unchanged)\n", updated.Name, updated.LocalURL)
	return apperr.ExitOK
}

func cmdServiceStart(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service start NAME [--foreground]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	foreground := false
	for _, a := range argv[1:] {
		if a == "--foreground" {
			foreground = true
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q\n", name)
		return apperr.ExitCLIValidation
	}
	// Bind credentials strictly to the profile the service was created with.
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	k, keyID, err := loadKeyForProfile(prof)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not enrolled in profile %q: run `ocliv login` first\n", prof)
		return apperr.ExitAuth
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(prof)
	}
	if _, rerr := validateRelayTarget(relayURL); rerr != nil {
		fmt.Fprintf(os.Stderr, "service start: %v\n", rerr)
		return apperr.ExitCLIValidation
	}

	if foreground {
		if rec.PublicationID != "" {
			st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+rec.PublicationID+"/enable")
			if callErr != nil {
				fmt.Fprintf(os.Stderr, "service start: relay enable failed: %v\n", callErr)
				return apperr.ExitRelayTLS
			}
			if st != http.StatusOK && st != http.StatusNotFound {
				fmt.Fprintf(os.Stderr, "service start: relay enable returned %d: %s\n", st, strings.TrimSpace(string(body)))
				return apperr.ExitAuth
			}
		}
		if _, err := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.DesiredState = config.DesiredEnabled
			r.LastRecoveryAction = ""
			return nil
		}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitInternal
		}
		return startServiceForeground(rec)
	}

	// 1. Provision user-level supervisor units & 0600 env file.
	if ops.provision != nil {
		if perr := ops.provision(rec, ops); perr != nil {
			_, _ = store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
				r.LastFailure = perr.Error()
				return nil
			})
			fmt.Fprintf(os.Stderr, "service start: supervisor provisioning failed: %v\n", perr)
			return apperr.ExitInternal
		}
	}

	// 2. If managed backend, start it before enabling/publishing.
	if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		if out, berr := ops.systemctl("start", rec.BackendUnit); berr != nil {
			fmt.Fprintf(os.Stderr, "service start: managed backend %s failed: %v (%s)\n", rec.BackendUnit, berr, out)
			return apperr.ExitLocalTarget
		}
	}

	// 3. Validate local backend reachability before mutating relay state.
	if len(rec.StdioCmd) == 0 {
		target, _, err := localTargetFromURL(rec.LocalURL)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitCLIValidation
		}
		var perr error
		attempts := 1
		if rec.BackendMode == config.BackendManaged {
			attempts = 20
		}
		for i := 0; i < attempts; i++ {
			perr = ops.probeLoc(target, 2*time.Second)
			if perr == nil {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if perr != nil {
			fmt.Fprintf(os.Stderr, "service start: local backend unreachable at %s: %v\n", target, perr)
			return apperr.ExitLocalTarget
		}
	}

	// 4. Enable publication on relay if it already exists.
	prevDesired := rec.DesiredState
	if rec.PublicationID != "" {
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+rec.PublicationID+"/enable")
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "service start: relay enable failed: %v\n", callErr)
			return apperr.ExitRelayTLS
		}
		if st != http.StatusOK && st != http.StatusNotFound {
			fmt.Fprintf(os.Stderr, "service start: relay enable returned %d: %s\n", st, strings.TrimSpace(string(body)))
			return apperr.ExitAuth
		}
	}

	updated, err := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
		r.DesiredState = config.DesiredEnabled
		r.LastRecoveryAction = ""
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec = updated

	// 5. Start the publisher unit; on failure roll back desired state.
	if out, err := ops.systemctl("start", rec.SystemdUnit); err != nil {
		if prevDesired != config.DesiredEnabled && rec.PublicationID != "" {
			_, _, _ = ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+rec.PublicationID+"/disable")
		}
		_, _ = store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
			if prevDesired != config.DesiredEnabled {
				r.DesiredState = config.DesiredDisabled
			}
			r.LastFailure = fmt.Sprintf("systemd start %s failed: %v (%s)", rec.SystemdUnit, err, out)
			r.LastRecoveryAction = "run `ocliv service start " + name + " --foreground` or check `systemctl --user status " + rec.SystemdUnit + "`"
			return nil
		})
		fmt.Fprintf(os.Stderr, "service start: %s\n", rec.LastFailure)
		return apperr.ExitInternal
	}

	// 6. Verify readiness (bounded poll so unit has time to register).
	var rep ServiceStatusReport
	for attempt := 0; attempt < 15; attempt++ {
		rep = inspectServiceStatus(rec, k, keyID, ops)
		if rep.State == ServiceStateServing || rep.State == ServiceStateFaulted || rep.State == ServiceStateRevoked {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	_, _ = store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
		if rep.PublicationID != "" {
			r.PublicationID = rep.PublicationID
		}
		if rep.PublicURL != "" {
			r.PublicURL = rep.PublicURL
		}
		if rep.StateGeneration > 0 {
			r.StateGeneration = rep.StateGeneration
		}
		if rep.State == ServiceStateServing {
			r.LastVerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
			r.LastFailure = ""
		}
		return nil
	})

	fmt.Printf("✓ service %s state=%s health=%s", rec.Name, rep.State, rep.Health)
	if rep.PublicURL != "" {
		fmt.Printf(" url=%s", rep.PublicURL)
	}
	fmt.Println()
	if rep.State == ServiceStateServing || rep.State == ServiceStateStarting {
		return apperr.ExitOK
	}
	return apperr.ExitInternal
}

func startServiceForeground(rec config.ServiceRecord) int {
	if rec.Profile != "" && rec.Profile != "default" {
		_ = os.Setenv("OCLIV_PROFILE", rec.Profile)
	}
	if rec.Type == "mcp" {
		args := []string{"--auth", rec.Auth, "--name", rec.Name}
		if rec.RelayURL != "" {
			args = append(args, "--relay", rec.RelayURL)
		}
		if len(rec.StdioCmd) > 0 {
			args = append(args, "--stdio", "--")
			args = append(args, rec.StdioCmd...)
		} else {
			args = append(args, "--local", rec.LocalURL)
		}
		return runMCPPublish(args, false)
	}
	target, _, err := localTargetFromURL(rec.LocalURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitCLIValidation
	}
	args := []string{target, "--name", rec.Name}
	if rec.Auth == "public" {
		args = append(args, "--public")
	}
	return cmdTunnel(args)
}

func cmdServiceRunPublisher(argv []string) int {
	var name string
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--name" || strings.HasPrefix(argv[i], "--name=") {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				return apperr.ExitCLIValidation
			}
			name = v
		}
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv service run-publisher --name NAME")
		return apperr.ExitCLIValidation
	}
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q\n", name)
		return apperr.ExitCLIValidation
	}
	if rec.DesiredState == config.DesiredDisabled {
		fmt.Fprintf(os.Stderr, "service %q is administratively disabled; refusing to publish\n", name)
		return apperr.ExitAuth
	}
	return startServiceForeground(rec)
}

func cmdServiceStop(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service stop NAME [--json]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	jsonOut := false
	for _, a := range argv[1:] {
		if a == "--json" {
			jsonOut = true
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q\n", name)
		return apperr.ExitCLIValidation
	}
	k, keyID, err := loadKeyForProfile(rec.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not enrolled in profile %q: run `ocliv login` first\n", rec.Profile)
		return apperr.ExitAuth
	}
	res := stopServiceAuthoritatively(store, rec, k, keyID, ops)
	if jsonOut {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else if res.Stopped {
		fmt.Printf("✓ service %s stopped (state=%s, retained_url=%s)\n", res.Name, res.State, res.RetainedURL)
	} else {
		fmt.Fprintf(os.Stderr, "service %s stop unconfirmed (state=%s): %s\n", res.Name, res.State, res.Detail)
	}
	if !res.Stopped {
		return apperr.ExitInternal
	}
	return apperr.ExitOK
}

// cmdServiceDisable is the emergency remote-first disable path that revokes
// public forwarding without depending on a functioning local supervisor.
func cmdServiceDisable(argv []string, ops serviceOps) int {
	return cmdServiceStop(argv, ops)
}

func cmdServiceRestart(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service restart NAME")
		return apperr.ExitCLIValidation
	}
	if code := cmdServiceStop([]string{argv[0]}, ops); code != apperr.ExitOK {
		return code
	}
	return cmdServiceStart([]string{argv[0]}, ops)
}

func cmdServiceStatus(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service status NAME [--json]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	jsonOut := false
	for _, a := range argv[1:] {
		if a == "--json" {
			jsonOut = true
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q\n", name)
		return apperr.ExitCLIValidation
	}
	k, keyID, err := loadKeyForProfile(rec.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not enrolled in profile %q: run `ocliv login` first\n", rec.Profile)
		return apperr.ExitAuth
	}
	rep := inspectServiceStatus(rec, k, keyID, ops)
	if jsonOut {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("service: %s (%s, profile=%s, mode=%s)\n", rep.Name, rep.Type, rep.Profile, rep.BackendMode)
		fmt.Printf("  desired: %s | state: %s | health: %s\n", rep.DesiredState, rep.State, rep.Health)
		fmt.Printf("  process: %s | relay: %s\n", rep.ProcessState, rep.RelayState)
		if rep.PublicURL != "" {
			fmt.Printf("  url:     %s (id=%s)\n", rep.PublicURL, rep.PublicationID)
		}
		fmt.Printf("  backend: %v (%s)\n", rep.BackendAvailable, rep.BackendDetail)
		fmt.Printf("  ingress: transport=%v verified=%v (%s)\n", rep.PublicTransport, rep.PublicVerified, rep.IngressDetail)
		if rep.LastFailure != "" {
			fmt.Printf("  failure: %s\n", rep.LastFailure)
		}
	}
	switch rep.Health {
	case HealthReady:
		return apperr.ExitOK
	case HealthUnknown:
		return apperr.ExitRelayTLS
	case HealthBlocked, HealthFailed:
		if !rep.BackendAvailable && rep.DesiredState == config.DesiredEnabled {
			return apperr.ExitLocalTarget
		}
		return apperr.ExitInternal
	default:
		return apperr.ExitOK
	}
}

func cmdServiceList(argv []string, ops serviceOps) int {
	jsonOut := false
	for _, a := range argv {
		if a == "--json" {
			jsonOut = true
		}
	}
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	recs, err := store.List()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	if jsonOut {
		b, _ := json.MarshalIndent(recs, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	if len(recs) == 0 {
		fmt.Println("no configured services")
		return apperr.ExitOK
	}
	fmt.Printf("%-18s %-5s %-15s %-11s %-10s %s\n", "NAME", "TYPE", "AUTH", "DESIRED", "PROFILE", "PUBLIC URL")
	for _, r := range recs {
		prof := r.Profile
		if prof == "" {
			prof = "default"
		}
		fmt.Printf("%-18s %-5s %-15s %-11s %-10s %s\n", r.Name, r.Type, r.Auth, r.DesiredState, prof, r.PublicURL)
	}
	return apperr.ExitOK
}

func cmdServiceRemove(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service remove NAME --confirm NAME")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	var confirm string
	for i := 1; i < len(argv); i++ {
		if argv[i] == "--confirm" || strings.HasPrefix(argv[i], "--confirm=") {
			v, ok := mcpFlagValue(argv, &i, "confirm")
			if !ok {
				return apperr.ExitCLIValidation
			}
			confirm = v
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if confirm != name {
		fmt.Fprintf(os.Stderr, "permanent removal requires `--confirm %s`\n", name)
		return apperr.ExitCLIValidation
	}
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q\n", name)
		return apperr.ExitCLIValidation
	}
	k, keyID, err := loadKeyForProfile(rec.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not enrolled in profile %q: run `ocliv login` first\n", rec.Profile)
		return apperr.ExitAuth
	}
	pubID, err := removeServiceAuthoritatively(store, rec, k, keyID, ops)
	if err != nil {
		fmt.Fprintf(os.Stderr, "service remove: %v\n", err)
		return apperr.ExitRelayTLS
	}
	if pubID != "" {
		fmt.Printf("✓ permanently removed service %s (publication %s revoked)\n", name, pubID)
	} else {
		fmt.Printf("✓ permanently removed service %s\n", name)
	}
	return apperr.ExitOK
}

func localTargetFromURL(raw string) (string, bool, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false, err
	}
	if u.Scheme == "unix" {
		return "unix:" + u.Path, false, nil
	}
	h := u.Hostname()
	p := u.Port()
	if p == "" {
		return "", false, fmt.Errorf("local URL %q missing port", raw)
	}
	if _, err := strconv.Atoi(p); err != nil {
		return "", false, fmt.Errorf("local URL %q invalid port", raw)
	}
	if h == "::1" {
		return "[::1]:" + p, true, nil
	}
	return "127.0.0.1:" + p, false, nil
}

func cmdServicePending(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service pending NAME [--json]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	jsonOut := false
	for _, a := range argv[1:] {
		if a == "--json" {
			jsonOut = true
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q\n", name)
		return apperr.ExitCLIValidation
	}
	k, keyID, err := loadKeyForProfile(rec.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not enrolled in profile %q: run `ocliv login` first\n", rec.Profile)
		return apperr.ExitAuth
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(rec.Profile)
	}
	pubID := rec.PublicationID
	if pubID == "" {
		foundID, _, found, rerr := resolveRelayPublication(relayURL, k, keyID, rec, ops)
		if rerr != nil || !found {
			fmt.Fprintf(os.Stderr, "service pending: no publication found for %q (%v)\n", name, rerr)
			return apperr.ExitInternal
		}
		pubID = foundID
	}
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/pending")
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "service pending: %v\n", callErr)
		return apperr.ExitRelayTLS
	}
	if st != http.StatusOK {
		fmt.Fprintf(os.Stderr, "service pending: relay returned %d: %s\n", st, strings.TrimSpace(string(body)))
		return apperr.ExitAuth
	}
	if jsonOut {
		fmt.Println(string(body))
		return apperr.ExitOK
	}
	var out struct {
		Pending []struct {
			ClientID     string `json:"client_id"`
			Name         string `json:"name"`
			RedirectURIs string `json:"redirect_uris"`
			Status       string `json:"status"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		fmt.Fprintln(os.Stderr, "invalid relay response")
		return apperr.ExitInternal
	}
	if len(out.Pending) == 0 {
		fmt.Println("no pending client approvals")
		return apperr.ExitOK
	}
	for _, p := range out.Pending {
		fmt.Printf("%s  name=%q status=%s redirects=%s\n", p.ClientID, p.Name, p.Status, p.RedirectURIs)
	}
	return apperr.ExitOK
}

func cmdServiceApprove(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service approve NAME [--client CLIENT_ID] [--direct]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	var clientID string
	var direct bool
	for i := 1; i < len(argv); i++ {
		if argv[i] == "--client" || strings.HasPrefix(argv[i], "--client=") {
			v, ok := mcpFlagValue(argv, &i, "client")
			if !ok {
				return apperr.ExitCLIValidation
			}
			clientID = v
		} else if argv[i] == "--direct" {
			direct = true
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	store, err := openServices()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q\n", name)
		return apperr.ExitCLIValidation
	}
	k, keyID, err := loadKeyForProfile(rec.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not enrolled in profile %q: run `ocliv login` first\n", rec.Profile)
		return apperr.ExitAuth
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(rec.Profile)
	}
	pubID := rec.PublicationID
	if pubID == "" {
		foundID, _, found, rerr := resolveRelayPublication(relayURL, k, keyID, rec, ops)
		if rerr != nil || !found {
			fmt.Fprintf(os.Stderr, "service approve: no publication found for %q (%v)\n", name, rerr)
			return apperr.ExitInternal
		}
		pubID = foundID
	}
	if clientID == "" {
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/pending")
		if callErr != nil || st != http.StatusOK {
			fmt.Fprintf(os.Stderr, "service approve: could not list pending clients (specify --client)\n")
			return apperr.ExitRelayTLS
		}
		var out struct {
			Pending []struct {
				ClientID string `json:"client_id"`
				Name     string `json:"name"`
			} `json:"pending"`
		}
		if json.Unmarshal(body, &out) != nil || len(out.Pending) != 1 {
			fmt.Fprintf(os.Stderr, "service approve: %d pending clients; specify --client <id>\n", len(out.Pending))
			return apperr.ExitCLIValidation
		}
		clientID = out.Pending[0].ClientID
	}
	path := "/v1/agent/mcp-routes/" + pubID + "/authz/approve/" + clientID
	if direct {
		path += "?direct=1"
	}
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, path)
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "service approve: %v\n", callErr)
		return apperr.ExitRelayTLS
	}
	if st != http.StatusOK {
		fmt.Fprintf(os.Stderr, "service approve: relay returned %d: %s\n", st, strings.TrimSpace(string(body)))
		return apperr.ExitAuth
	}
	var res struct {
		ClientID      string `json:"client_id"`
		PairingSecret string `json:"pairing_secret"`
		Direct        bool   `json:"direct"`
	}
	if err := json.Unmarshal(body, &res); err != nil || (!direct && res.PairingSecret == "") {
		fmt.Fprintln(os.Stderr, "invalid relay approve response")
		return apperr.ExitInternal
	}
	if direct || res.Direct {
		fmt.Printf("✓ approved client %s for %s (route=%s, direct; pairing bypassed)\n", res.ClientID, name, pubID)
		return apperr.ExitOK
	}
	fmt.Printf("✓ approved client %s for %s (route=%s)\n", res.ClientID, name, pubID)
	fmt.Printf("Pairing secret (single-use; enter in consent form):\n%s\n", res.PairingSecret)
	return apperr.ExitOK
}
