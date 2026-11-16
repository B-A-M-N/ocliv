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

// ServiceStatusReport is the structured diagnostic output for `ocliv service status --json`.
type ServiceStatusReport struct {
	Name               string `json:"name"`
	Type               string `json:"type"`
	DesiredState       string `json:"desired_state"`
	State              string `json:"state"`
	Health             string `json:"health"`
	ProcessState       string `json:"process_state"`
	RelayState         string `json:"relay_state"`
	PublicationID      string `json:"publication_id,omitempty"`
	LeaseID            string `json:"lease_id,omitempty"`
	PublicURL          string `json:"public_url,omitempty"`
	AuthProfile        string `json:"auth_profile"`
	BackendAvailable   bool   `json:"backend_available"`
	BackendDetail      string `json:"backend_detail,omitempty"`
	IngressReady       bool   `json:"ingress_ready"`
	IngressDetail      string `json:"ingress_detail,omitempty"`
	LastVerifiedAt     string `json:"last_verified_at,omitempty"`
	LastFailure        string `json:"last_failure,omitempty"`
	LastRecoveryAction string `json:"last_recovery_action,omitempty"`
}

type serviceStopResult struct {
	Name          string `json:"name"`
	Stopped       bool   `json:"stopped"`
	State         string `json:"state"`
	PublicationID string `json:"publication_id,omitempty"`
	RetainedURL   string `json:"retained_url,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// serviceOps isolates external interactions (systemd, relay mgmt, probes)
// so both production and hermetic unit/integration tests use the same logic.
type serviceOps struct {
	systemctl func(args ...string) (string, error)
	mgmtCall  func(relayURL string, k *identity.KeyPair, keyID, method, path string) (int, []byte, error)
	probeLoc  func(target string, timeout time.Duration) error
	probePub  func(publicURL string, timeout time.Duration) (int, error)
}

func defaultServiceOps() serviceOps {
	return serviceOps{
		systemctl: func(args ...string) (string, error) {
			out, err := exec.Command("systemctl", args...).CombinedOutput()
			return strings.TrimSpace(string(out)), err
		},
		mgmtCall: mgmtCall,
		probeLoc: agent.ProbeLocal,
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
		fmt.Fprintln(os.Stderr, "usage: ocliv service add|update|start|stop|restart|status|list|remove ...")
		return apperr.ExitCLIValidation
	}
	ops := defaultServiceOps()
	switch argv[0] {
	case "add":
		return cmdServiceAdd(argv[1:])
	case "update":
		return cmdServiceUpdate(argv[1:])
	case "start":
		return cmdServiceStart(argv[1:], ops)
	case "stop":
		return cmdServiceStop(argv[1:], ops)
	case "restart":
		return cmdServiceRestart(argv[1:], ops)
	case "status":
		return cmdServiceStatus(argv[1:], ops)
	case "list":
		return cmdServiceList(argv[1:], ops)
	case "remove":
		return cmdServiceRemove(argv[1:], ops)
	default:
		fmt.Fprintf(os.Stderr, "unknown service command %q\n", argv[0])
		return apperr.ExitCLIValidation
	}
}

func openServices() (*config.ServiceStore, error) {
	dir, err := config.DataDir()
	if err != nil {
		return nil, err
	}
	return config.OpenServiceStore(dir), nil
}

func cmdServiceAdd(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service add NAME --type mcp|http (--local URL | --stdio -- CMD [ARGS...]) [--auth MODE] [--relay URL] [--unit UNIT]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	if err := config.ValidateServiceName(name); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitCLIValidation
	}
	var svcType, localURL, auth, relayURL, unit string
	var stdio bool
	var stdioCmd []string
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			stdioCmd = argv[i+1:]
			i = len(argv)
		case a == "--stdio":
			stdio = true
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
			fmt.Fprintln(os.Stderr, "--local URL or --stdio is required")
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
	if relayURL != "" {
		if _, err := validateRelayTarget(relayURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitCLIValidation
		}
	} else {
		relayURL = agentRelayURL()
	}
	store, err := openServices()
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
	rec := config.ServiceRecord{
		Name:         name,
		Type:         svcType,
		LocalURL:     localURL,
		StdioCmd:     stdioCmd,
		Auth:         auth,
		RelayURL:     relayURL,
		Profile:      config.ActiveProfile(),
		DesiredState: config.DesiredConfigured,
		SystemdUnit:  unit,
	}
	if err := store.Put(rec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	fmt.Printf("✓ registered service %s (%s, auth=%s, desired=%s)\n", rec.Name, rec.Type, rec.Auth, rec.DesiredState)
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
			rec.LocalURL = v
		case a == "--relay" || strings.HasPrefix(a, "--relay="):
			v, ok := mcpFlagValue(argv, &i, "relay")
			if !ok {
				return apperr.ExitCLIValidation
			}
			if _, err := validateRelayTarget(v); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return apperr.ExitCLIValidation
			}
			rec.RelayURL = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	if err := store.Put(rec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	fmt.Printf("✓ updated service %s (local=%s; permanent identity unchanged)\n", rec.Name, rec.LocalURL)
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
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURL()
	}
	// If this service already has a publication on the relay, explicitly
	// enable desired_enabled=1 before starting the publisher.
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
	rec.DesiredState = config.DesiredEnabled
	rec.LastRecoveryAction = ""
	if err := store.Put(rec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	if foreground {
		return startServiceForeground(rec)
	}
	if out, err := ops.systemctl("start", rec.SystemdUnit); err != nil {
		rec.LastFailure = fmt.Sprintf("systemd start %s failed: %v (%s)", rec.SystemdUnit, err, out)
		rec.LastRecoveryAction = "run `ocliv service start " + name + " --foreground` or check `systemctl status " + rec.SystemdUnit + "`"
		_ = store.Put(rec)
		fmt.Fprintln(os.Stderr, rec.LastFailure)
		return apperr.ExitInternal
	}
	rep := inspectServiceStatus(rec, k, keyID, ops)
	if rep.PublicationID != "" {
		rec.PublicationID = rep.PublicationID
	}
	if rep.PublicURL != "" {
		rec.PublicURL = rep.PublicURL
	}
	if rep.State == ServiceStateServing {
		rec.LastVerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
		rec.LastFailure = ""
	}
	_ = store.Put(rec)
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
	// Generic HTTP tunnel sharing the same service record identity.
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
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
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

// stopServiceAuthoritatively enforces the 7-step stop contract (Section 4).
// It never deletes/unpublishes the route and never converts uncertainty into success.
func stopServiceAuthoritatively(store *config.ServiceStore, rec config.ServiceRecord, k *identity.KeyPair, keyID string, ops serviceOps) serviceStopResult {
	res := serviceStopResult{
		Name:          rec.Name,
		PublicationID: rec.PublicationID,
		RetainedURL:   rec.PublicURL,
	}
	// 1-2. Record desired disabled state durably before stopping.
	rec.DesiredState = config.DesiredDisabled
	if err := store.Put(rec); err != nil {
		res.State = ServiceStateUnknown
		res.Detail = "failed to persist desired disabled state: " + err.Error()
		return res
	}
	// 3-4. Request supervisor termination and verify process is inactive.
	if rec.SystemdUnit != "" {
		if out, err := ops.systemctl("stop", rec.SystemdUnit); err != nil {
			// If the unit is not loaded/inactive, check is-active before failing.
			act, _ := ops.systemctl("is-active", rec.SystemdUnit)
			if act == "active" || act == "activating" || act == "deactivating" {
				res.State = "STOP_UNCONFIRMED"
				res.Detail = fmt.Sprintf("systemd stop failed: %v (%s)", err, out)
				return res
			}
		}
		if act, _ := ops.systemctl("is-active", rec.SystemdUnit); act == "active" || act == "activating" {
			res.State = "STOP_UNCONFIRMED"
			res.Detail = "publisher unit still active after stop"
			return res
		}
	}
	// 5. Confirm relay disable & lease/session teardown.
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURL()
	}
	pubID := rec.PublicationID
	if pubID == "" {
		// Look up by service name in relay inventory.
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes")
		if callErr != nil {
			res.State = ServiceStateUnknown
			res.Detail = "relay unreachable during stop confirmation: " + callErr.Error()
			return res
		}
		if st == http.StatusOK {
			var inv struct {
				Publications []struct {
					RouteID string  `json:"route_id"`
					Name    string  `json:"pub_name"`
					URL     *string `json:"url"`
				} `json:"publications"`
			}
			if json.Unmarshal(body, &inv) == nil {
				for _, p := range inv.Publications {
					if p.Name == rec.Name {
						pubID = p.RouteID
						if p.URL != nil {
							res.RetainedURL = *p.URL
							rec.PublicURL = *p.URL
						}
						rec.PublicationID = pubID
						_ = store.Put(rec)
						break
					}
				}
			}
		}
	}
	if pubID != "" {
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/disable")
		if callErr != nil {
			res.State = ServiceStateUnknown
			res.Detail = "relay unreachable during disable confirmation: " + callErr.Error()
			return res
		}
		if st != http.StatusOK && st != http.StatusNotFound {
			res.State = "STOP_UNCONFIRMED"
			res.Detail = fmt.Sprintf("relay disable returned %d: %s", st, strings.TrimSpace(string(body)))
			return res
		}
		if st == http.StatusOK {
			var dis struct {
				DesiredEnabled bool `json:"desired_enabled"`
				SessionLive    bool `json:"session_live"`
			}
			if err := json.Unmarshal(body, &dis); err != nil || dis.DesiredEnabled || dis.SessionLive {
				res.State = "STOP_UNCONFIRMED"
				res.Detail = "relay did not confirm session teardown"
				return res
			}
		}
	}
	// 6. Confirm public-route admission is denied (404/503, never 200/401).
	if res.RetainedURL != "" {
		code, err := ops.probePub(res.RetainedURL, 5*time.Second)
		if err != nil {
			res.State = ServiceStateUnknown
			res.Detail = "public route denial probe failed: " + err.Error()
			return res
		}
		if code != http.StatusNotFound && code != http.StatusServiceUnavailable {
			res.State = "STOP_UNCONFIRMED"
			res.Detail = fmt.Sprintf("public route still answered HTTP %d after stop", code)
			return res
		}
	}
	// 7. Stop contract satisfied.
	res.Stopped = true
	res.State = ServiceStateDisabled
	return res
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
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	rep := inspectServiceStatus(rec, k, keyID, ops)
	if jsonOut {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("service: %s (%s)\n", rep.Name, rep.Type)
		fmt.Printf("  desired: %s | state: %s | health: %s\n", rep.DesiredState, rep.State, rep.Health)
		fmt.Printf("  process: %s | relay: %s\n", rep.ProcessState, rep.RelayState)
		if rep.PublicURL != "" {
			fmt.Printf("  url:     %s (id=%s)\n", rep.PublicURL, rep.PublicationID)
		}
		fmt.Printf("  backend: %v (%s)\n", rep.BackendAvailable, rep.BackendDetail)
		fmt.Printf("  ingress: %v (%s)\n", rep.IngressReady, rep.IngressDetail)
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

func inspectServiceStatus(rec config.ServiceRecord, k *identity.KeyPair, keyID string, ops serviceOps) ServiceStatusReport {
	rep := ServiceStatusReport{
		Name:               rec.Name,
		Type:               rec.Type,
		DesiredState:       rec.DesiredState,
		State:              ServiceStateConfigured,
		Health:             HealthUnknown,
		ProcessState:       "unknown",
		RelayState:         "unknown",
		PublicationID:      rec.PublicationID,
		PublicURL:          rec.PublicURL,
		AuthProfile:        rec.Auth,
		LastVerifiedAt:     rec.LastVerifiedAt,
		LastFailure:        rec.LastFailure,
		LastRecoveryAction: rec.LastRecoveryAction,
	}
	// 1. Supervisor process state.
	if rec.SystemdUnit != "" {
		act, err := ops.systemctl("is-active", rec.SystemdUnit)
		if act != "" {
			rep.ProcessState = act
		} else if err != nil {
			rep.ProcessState = "inactive"
		}
	}
	// 2. Local backend availability.
	if len(rec.StdioCmd) > 0 {
		rep.BackendAvailable = true
		rep.BackendDetail = "stdio subprocess configured"
	} else if target, _, err := localTargetFromURL(rec.LocalURL); err != nil {
		rep.BackendDetail = err.Error()
	} else if perr := ops.probeLoc(target, 2*time.Second); perr != nil {
		rep.BackendDetail = perr.Error()
	} else {
		rep.BackendAvailable = true
		rep.BackendDetail = "reachable"
	}
	// 3. Authenticated relay inventory.
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURL()
	}
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes")
	if callErr != nil {
		rep.State = ServiceStateUnknown
		rep.Health = HealthUnknown
		rep.RelayState = "unreachable"
		rep.IngressDetail = callErr.Error()
		return rep
	}
	if st != http.StatusOK {
		rep.State = ServiceStateUnknown
		rep.Health = HealthUnknown
		rep.RelayState = fmt.Sprintf("http_%d", st)
		return rep
	}
	var inv struct {
		Publications []struct {
			RouteID          string  `json:"route_id"`
			Name             string  `json:"pub_name"`
			URL              *string `json:"url"`
			LeaseID          *string `json:"lease_id"`
			PublicationState string  `json:"publication_state"`
			DesiredEnabled   bool    `json:"desired_enabled"`
			SessionLive      bool    `json:"session_live"`
			Admission        string  `json:"admission"`
			AdmissionReason  string  `json:"admission_reason"`
		} `json:"publications"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		rep.State = ServiceStateUnknown
		rep.Health = HealthUnknown
		rep.RelayState = "invalid_json"
		return rep
	}
	var matched bool
	var pubState, admission, admissionReason string
	var relayDesired, sessionLive bool
	for _, p := range inv.Publications {
		if (rec.PublicationID != "" && p.RouteID == rec.PublicationID) || p.Name == rec.Name {
			matched = true
			rep.PublicationID = p.RouteID
			if p.URL != nil {
				rep.PublicURL = *p.URL
			}
			if p.LeaseID != nil {
				rep.LeaseID = *p.LeaseID
			}
			pubState = p.PublicationState
			relayDesired = p.DesiredEnabled
			sessionLive = p.SessionLive
			admission = p.Admission
			admissionReason = p.AdmissionReason
			break
		}
	}
	if !matched {
		rep.RelayState = "not_registered"
		if rec.DesiredState == config.DesiredDisabled {
			rep.State = ServiceStateDisabled
			rep.Health = HealthReady
		} else if rec.DesiredState == config.DesiredConfigured {
			rep.State = ServiceStateConfigured
			rep.Health = HealthReady
		} else if rep.ProcessState == "activating" {
			rep.State = ServiceStateStarting
			rep.Health = HealthDegraded
		} else {
			rep.State = ServiceStateOffline
			rep.Health = HealthFailed
		}
		return rep
	}
	rep.RelayState = pubState
	if pubState == "REVOKED" {
		rep.State = ServiceStateRevoked
		rep.Health = HealthBlocked
		rep.IngressDetail = "publication revoked"
		return rep
	}
	if rec.DesiredState == config.DesiredDisabled || !relayDesired {
		rep.State = ServiceStateDisabled
		if sessionLive {
			rep.Health = HealthDegraded
			rep.IngressDetail = "disabled but session still live"
		} else {
			rep.Health = HealthReady
			rep.IngressDetail = "disabled (404)"
		}
		return rep
	}
	// Desired enabled:
	if admission == "READY" && sessionLive && rep.BackendAvailable {
		if rep.PublicURL != "" {
			code, err := ops.probePub(rep.PublicURL, 3*time.Second)
			if err == nil && (code == http.StatusUnauthorized || code == http.StatusOK) {
				rep.IngressReady = true
				rep.IngressDetail = fmt.Sprintf("HTTP %d", code)
				rep.State = ServiceStateServing
				rep.Health = HealthReady
				return rep
			}
			rep.IngressDetail = fmt.Sprintf("probe code=%d err=%v", code, err)
			rep.State = ServiceStateOffline
			rep.Health = HealthDegraded
			return rep
		}
		rep.State = ServiceStateServing
		rep.Health = HealthReady
		return rep
	}
	if rep.ProcessState == "failed" {
		rep.State = ServiceStateFaulted
		rep.Health = HealthFailed
		rep.IngressDetail = admissionReason
		return rep
	}
	if rep.ProcessState == "activating" {
		rep.State = ServiceStateStarting
		rep.Health = HealthDegraded
		rep.IngressDetail = admissionReason
		return rep
	}
	rep.State = ServiceStateOffline
	rep.Health = HealthFailed
	rep.IngressDetail = admissionReason
	return rep
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
	fmt.Printf("%-18s %-5s %-15s %-11s %s\n", "NAME", "TYPE", "AUTH", "DESIRED", "PUBLIC URL")
	for _, r := range recs {
		fmt.Printf("%-18s %-5s %-15s %-11s %s\n", r.Name, r.Type, r.Auth, r.DesiredState, r.PublicURL)
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
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	if rec.SystemdUnit != "" {
		_, _ = ops.systemctl("stop", rec.SystemdUnit)
	}
	if rec.PublicationID != "" {
		relayURL := rec.RelayURL
		if relayURL == "" {
			relayURL = agentRelayURL()
		}
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodDelete, "/v1/agent/mcp-routes/"+rec.PublicationID)
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "service remove: relay delete failed: %v\n", callErr)
			return apperr.ExitRelayTLS
		}
		if st != http.StatusOK && st != http.StatusNotFound {
			fmt.Fprintf(os.Stderr, "service remove: relay delete returned %d: %s\n", st, strings.TrimSpace(string(body)))
			return apperr.ExitInternal
		}
	}
	if _, err := store.Delete(name); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	fmt.Printf("✓ permanently removed service %s\n", name)
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
