package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/lease"
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
	Name                string `json:"name"`
	Stopped             bool   `json:"stopped"`
	RemoteDisabled      bool   `json:"remote_disabled"`
	RemoteDisableStatus string `json:"remote_disable_status"` // CONFIRMED | UNCONFIRMED | NOT_APPLICABLE
	LocalStopped        bool   `json:"local_stopped"`
	State               string `json:"state"`
	PublicationID       string `json:"publication_id,omitempty"`
	RetainedURL         string `json:"retained_url,omitempty"`
	Detail              string `json:"detail,omitempty"`
}

// serviceOps isolates external interactions (systemd --user, relay mgmt, probes)
// so both production and hermetic unit/integration tests use the same logic.
type serviceOps struct {
	systemctl    func(args ...string) (string, error)
	loginctl     func(args ...string) (string, error)
	mgmtCall     func(relayURL string, k *identity.KeyPair, keyID, method, path string) (int, []byte, error)
	mgmtCallBody func(relayURL string, k *identity.KeyPair, keyID, method, path string, reqBody []byte) (int, []byte, error)
	probeLoc     func(target string, timeout time.Duration) error
	probePub     func(publicURL string, timeout time.Duration) (int, error)
	probeEdge    func(publicURL string, timeout time.Duration) (int, error)
	provision    func(rec config.ServiceRecord, ops serviceOps) error
}

func defaultServiceOps() serviceOps {
	return serviceOps{
		systemctl: func(args ...string) (string, error) {
			uargs := append([]string{"--user"}, args...)
			out, err := exec.Command("systemctl", uargs...).CombinedOutput()
			return strings.TrimSpace(string(out)), err
		},
		loginctl: func(args ...string) (string, error) {
			out, err := exec.Command("loginctl", args...).CombinedOutput()
			return strings.TrimSpace(string(out)), err
		},
		mgmtCall:     mgmtCall,
		mgmtCallBody: mgmtCallBody,
		probeLoc:     agent.ProbeLocal,
		provision:    provisionUserSupervisor,
		probeEdge: func(publicURL string, timeout time.Duration) (int, error) {
			c, err := mgmtHTTPClient(timeout)
			if err != nil {
				return 0, err
			}
			defer c.CloseIdleConnections()
			// Never follow cross-origin or unexpected redirects during edge proof.
			c.CheckRedirect = func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}
			u, err := url.Parse(strings.TrimSpace(publicURL))
			if err != nil || u.Scheme == "" || u.Host == "" {
				return 0, fmt.Errorf("invalid public URL %q", publicURL)
			}
			healthURL := u.Scheme + "://" + u.Host + "/_ocliv/healthz"
			req, err := http.NewRequest(http.MethodHead, healthURL, nil)
			if err != nil {
				return 0, err
			}
			resp, err := c.Do(req)
			if err != nil {
				return 0, err
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && resp.Header.Get("X-Ocliv-Edge") != "ok" {
				return resp.StatusCode, fmt.Errorf("edge healthz returned 200 without X-Ocliv-Edge: ok header")
			}
			return resp.StatusCode, nil
		},
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

// requireUserContext refuses accidental root execution of user-scoped
// lifecycle commands (host, service, runtime, restart, stop, remove) so root
// never creates root-owned user-systemd state or modifies /root (P1-12).
func requireUserContext(cmdName string, allowRoot bool) error {
	if os.Geteuid() == 0 && !allowRoot {
		return fmt.Errorf("refusing to run user-level `ocliv %s` as root (run as your normal user, or pass --allow-root)", cmdName)
	}
	return nil
}

// normalizeManagedBackendConfig resolves and validates managed backend paths
// consistently for both `service add` and `service update` (P1-10).
func normalizeManagedBackendConfig(execBin, workDir, envFile string) (string, string, string, error) {
	if execBin != "" {
		if !filepath.IsAbs(execBin) {
			resolved, err := exec.LookPath(execBin)
			if err != nil {
				return "", "", "", fmt.Errorf("managed executable %q not found on PATH: %w", execBin, err)
			}
			execBin = resolved
		}
		abs, err := filepath.Abs(execBin)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid executable path %q: %w", execBin, err)
		}
		execBin = abs
	}
	if workDir != "" {
		abs, err := filepath.Abs(workDir)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid --workdir %q: %w", workDir, err)
		}
		workDir = abs
	}
	if envFile != "" {
		abs, err := filepath.Abs(envFile)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid --env-file %q: %w", envFile, err)
		}
		envFile = abs
	}
	return execBin, workDir, envFile, nil
}

// loadBackendEnvFileStrict reads a configured backend env file via O_NOFOLLOW,
// failing closed if the file is missing, unreadable, symlinked, or malformed,
// and merges entries deterministically over baseEnv without duplicates (P1-11).
func loadBackendEnvFileStrict(path string, baseEnv []string) ([]string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening configured backend env-file %s: %w", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat backend env-file %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("backend env-file %s must be a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("backend env-file %s has unsafe mode %04o (want 0600)", path, st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if int(sys.Uid) != os.Geteuid() {
			return nil, fmt.Errorf("backend env-file %s is owned by uid %d (want %d)", path, sys.Uid, os.Geteuid())
		}
	}
	const maxBackendEnvBytes = 1 << 20 // 1 MiB cap
	raw, err := io.ReadAll(io.LimitReader(f, maxBackendEnvBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading backend env-file %s: %w", path, err)
	}
	if len(raw) > maxBackendEnvBytes {
		return nil, fmt.Errorf("backend env-file %s exceeds maximum size (%d bytes)", path, maxBackendEnvBytes)
	}
	if strings.ContainsRune(string(raw), '\x00') {
		return nil, fmt.Errorf("backend env-file %s contains NUL byte", path)
	}
	overrides := map[string]string{}
	var order []string
	for idx, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("backend env-file %s line %d: expected KEY=VALUE", path, idx+1)
		}
		k := strings.TrimSpace(line[:eq])
		v := line[eq+1:]
		if !isValidEnvKey(k) {
			return nil, fmt.Errorf("backend env-file %s line %d: invalid env key %q", path, idx+1, k)
		}
		if _, exists := overrides[k]; !exists {
			order = append(order, k)
		}
		overrides[k] = v
	}
	// Replace existing baseEnv keys deterministically; append new keys in order.
	out := make([]string, 0, len(baseEnv)+len(order))
	replaced := map[string]bool{}
	for _, entry := range baseEnv {
		if eq := strings.IndexByte(entry, '='); eq > 0 {
			k := entry[:eq]
			if v, ok := overrides[k]; ok {
				if !replaced[k] {
					out = append(out, k+"="+v)
					replaced[k] = true
				}
				continue
			}
		}
		out = append(out, entry)
	}
	for _, k := range order {
		if !replaced[k] {
			out = append(out, k+"="+overrides[k])
		}
	}
	return out, nil
}

func isValidEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isAlpha {
			return false
		}
		if !isAlpha && !isDigit {
			return false
		}
	}
	return true
}

func cmdService(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service add|update|start|stop|disable|restart|status|list|remove ...")
		return apperr.ExitCLIValidation
	}
	if argv[0] != "run-publisher" && argv[0] != "run-backend" {
		if err := requireUserContext("service "+argv[0], false); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
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
	case "reconcile":
		return cmdServiceReconcile(argv[1:], ops)
	case "run-publisher":
		return cmdServiceRunPublisher(argv[1:])
	case "run-backend":
		return cmdServiceRunBackend(argv[1:])
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
	var svcType, localURL, auth, relayURL, unit, execBin, workDir, envFile string
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
		case a == "--workdir" || strings.HasPrefix(a, "--workdir="):
			v, ok := mcpFlagValue(argv, &i, "workdir")
			if !ok {
				return apperr.ExitCLIValidation
			}
			workDir = v
		case a == "--env-file" || strings.HasPrefix(a, "--env-file="):
			v, ok := mcpFlagValue(argv, &i, "env-file")
			if !ok {
				return apperr.ExitCLIValidation
			}
			envFile = v
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
	rec, backendStatus, code, err := registerHostedService(serviceAddRequest{
		Name:           name,
		Type:           svcType,
		BackendMode:    backendMode,
		BackendExec:    execBin,
		BackendArgs:    execArgs,
		BackendWorkDir: workDir,
		BackendEnvFile: envFile,
		LocalURL:       localURL,
		StdioCmd:       stdioCmd,
		Auth:           auth,
		RelayURL:       relayURL,
		Profile:        prof,
		Unit:           unit,
	}, ops)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return code
	}
	fmt.Printf("Service %s configured (profile=%s, mode=%s).\n", rec.Name, rec.Profile, rec.BackendMode)
	fmt.Printf("Backend: %s\n", backendStatus)
	fmt.Printf("Publisher: not installed\n")
	fmt.Printf("Public URL: not yet allocated\n")
	fmt.Printf("Next: ocliv service start %s\n", rec.Name)
	return apperr.ExitOK
}

type serviceAddRequest struct {
	Name           string
	Type           string
	BackendMode    string
	BackendExec    string
	BackendArgs    []string
	BackendWorkDir string
	BackendEnvFile string
	LocalURL       string
	StdioCmd       []string
	Auth           string
	RelayURL       string
	Profile        string
	Unit           string
}

// validateServiceAddRequest enforces all core hosted-service invariants in one
// pure function below the CLI parser so both `ocliv service add` and
// `ocliv host` reject invalid combinations before writing any state.
func validateServiceAddRequest(req *serviceAddRequest) error {
	if req.BackendMode == config.BackendManaged {
		normExec, normWD, normEnv, nerr := normalizeManagedBackendConfig(req.BackendExec, req.BackendWorkDir, req.BackendEnvFile)
		if nerr != nil {
			return nerr
		}
		req.BackendExec = normExec
		req.BackendWorkDir = normWD
		req.BackendEnvFile = normEnv
	}
	if len(req.StdioCmd) > 0 && req.StdioCmd[0] != "" && !filepath.IsAbs(req.StdioCmd[0]) {
		if resolved, rerr := exec.LookPath(req.StdioCmd[0]); rerr == nil {
			if abs, aerr := filepath.Abs(resolved); aerr == nil {
				req.StdioCmd[0] = abs
			} else {
				req.StdioCmd[0] = resolved
			}
		}
	}
	if err := config.ValidateServiceName(req.Name); err != nil {
		return err
	}
	if req.Type == "" {
		req.Type = "mcp"
	}
	if req.Type != "mcp" && req.Type != "http" {
		return fmt.Errorf("invalid --type %q (want mcp or http)", req.Type)
	}
	if req.BackendMode == "" {
		req.BackendMode = config.BackendAttached
	}
	if req.BackendMode != config.BackendAttached && req.BackendMode != config.BackendManaged {
		return fmt.Errorf("invalid backend mode %q", req.BackendMode)
	}
	hasStdio := len(req.StdioCmd) > 0
	if hasStdio && req.BackendMode == config.BackendManaged {
		return fmt.Errorf("--stdio and --manage cannot be combined")
	}
	if hasStdio && req.LocalURL != "" {
		return fmt.Errorf("--stdio and --local/--attach cannot be combined")
	}
	if req.BackendMode == config.BackendManaged {
		if strings.TrimSpace(req.BackendExec) == "" {
			return fmt.Errorf("--manage requires --exec BIN")
		}
		if strings.TrimSpace(req.LocalURL) == "" {
			return fmt.Errorf("--manage requires --local URL")
		}
	}
	if hasStdio {
		if req.Type != "mcp" {
			return fmt.Errorf("--stdio requires --type mcp")
		}
		if req.Auth == "" {
			req.Auth = "ocliv-managed"
		}
		if req.Auth != "ocliv-managed" {
			return fmt.Errorf("--stdio requires --auth ocliv-managed")
		}
	} else {
		if strings.TrimSpace(req.LocalURL) == "" {
			return fmt.Errorf("--attach/--local URL or --stdio is required")
		}
		if err := config.ValidateServiceLocalURL(req.LocalURL); err != nil {
			return err
		}
	}
	if req.Type == "mcp" {
		if req.Auth == "" {
			req.Auth = "ocliv-managed"
		}
		if req.Auth != "ocliv-managed" && req.Auth != "upstream-oauth" {
			return fmt.Errorf("invalid MCP --auth %q (want ocliv-managed or upstream-oauth)", req.Auth)
		}
	} else {
		if err := lease.ValidateLabel(canonicalHTTPLabel(req.Name)); err != nil {
			return fmt.Errorf("HTTP service name %q is not a valid DNS wire label (use lowercase letters, digits, hyphens; no underscores): %w", req.Name, err)
		}
		if req.Auth == "" {
			req.Auth = "protected"
		}
		if req.Auth != "protected" && req.Auth != "public" {
			return fmt.Errorf("invalid HTTP --auth %q (want protected or public)", req.Auth)
		}
	}
	if req.RelayURL != "" {
		if _, err := validateRelayTarget(req.RelayURL); err != nil {
			return err
		}
	}
	return nil
}

// registerHostedService validates and commits a new hosted service record
// without writing to stdout, so callers (including `--json` commands) control
// all presentation cleanly.
func registerHostedService(req serviceAddRequest, ops serviceOps) (config.ServiceRecord, string, int, error) {
	if err := validateServiceAddRequest(&req); err != nil {
		return config.ServiceRecord{}, "", apperr.ExitCLIValidation, err
	}
	prof := req.Profile
	if prof == "" {
		prof = config.ActiveProfile()
	}
	relayURL := req.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(prof)
	}
	store, err := openServicesForProfile(prof)
	if err != nil {
		return config.ServiceRecord{}, "", apperr.ExitInternal, err
	}
	wireLabel := canonicalHTTPLabel(req.Name)
	inst, ierr := serviceInstanceID(prof, req.Name)
	if ierr != nil {
		return config.ServiceRecord{}, "", apperr.ExitCLIValidation, ierr
	}
	unit := req.Unit
	if unit == "" {
		unit = "ocliv-publisher@" + inst + ".service"
	}
	backendUnit := ""
	if req.BackendMode == config.BackendManaged {
		backendUnit = "ocliv-backend@" + inst + ".service"
	}
	ownerKeyID := ""
	if _, kid, kerr := loadKeyForProfile(prof); kerr == nil {
		ownerKeyID = kid
	}
	svcID, idErr := config.NewServiceID()
	if idErr != nil {
		return config.ServiceRecord{}, "", apperr.ExitInternal, idErr
	}
	rec := config.ServiceRecord{
		Name:           req.Name,
		Type:           req.Type,
		BackendMode:    req.BackendMode,
		BackendExec:    req.BackendExec,
		BackendArgs:    req.BackendArgs,
		BackendWorkDir: req.BackendWorkDir,
		BackendEnvFile: req.BackendEnvFile,
		LocalURL:       req.LocalURL,
		StdioCmd:       req.StdioCmd,
		Auth:           req.Auth,
		RelayURL:       relayURL,
		Profile:        prof,
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     svcID,
			Name:          req.Name,
			WireLabel:     wireLabel,
			OwnerKeyID:    ownerKeyID,
			RelayID:       relayAuthority(relayURL),
		},
		DesiredState:     config.DesiredConfigured,
		ConfigGeneration: 1,
		SystemdUnit:      unit,
		BackendUnit:      backendUnit,
	}
	rec, err = store.CreateAtomic(rec)
	if err != nil {
		if errors.Is(err, config.ErrServiceAlreadyExists) || errors.Is(err, config.ErrServiceLabelCollision) {
			return config.ServiceRecord{}, "", apperr.ExitCLIValidation, err
		}
		return config.ServiceRecord{}, "", apperr.ExitInternal, err
	}
	backendStatus := "not running"
	if target, _, err := localTargetFromURL(rec.LocalURL); err == nil {
		if ops.probeLoc != nil && ops.probeLoc(target, 500*time.Millisecond) == nil {
			backendStatus = "reachable"
		}
	} else if len(rec.StdioCmd) > 0 {
		backendStatus = "stdio configured"
	}
	return rec, backendStatus, apperr.ExitOK, nil
}

func relayAuthority(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(rawURL)
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func verifyServiceIdentityOwnership(rec config.ServiceRecord, keyID, relayURL string) error {
	if rec.Identity == nil {
		return nil
	}
	if rec.Identity.OwnerKeyID != "" && keyID != "" && rec.Identity.OwnerKeyID != keyID {
		return fmt.Errorf("ownership mismatch for service %q: registered owner key %s != current key %s (cross-key transfer requires explicit migration)", rec.Name, rec.Identity.OwnerKeyID, keyID)
	}
	wantRelay := relayAuthority(relayURL)
	if rec.Identity.RelayID != "" && wantRelay != "" && rec.Identity.RelayID != wantRelay {
		return fmt.Errorf("relay authority mismatch for service %q: registered relay %s != %s", rec.Name, rec.Identity.RelayID, wantRelay)
	}
	return nil
}

func cmdServiceUpdate(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service update NAME [--local URL] [--exec BIN] [--relay URL]")
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
	var newLocal, newRelay, newExec, newWorkDir, newEnvFile string
	var newExecArgs []string
	hasExecArgs := false
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			newExecArgs = argv[i+1:]
			hasExecArgs = true
			i = len(argv)
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
		case a == "--exec" || strings.HasPrefix(a, "--exec="):
			v, ok := mcpFlagValue(argv, &i, "exec")
			if !ok {
				return apperr.ExitCLIValidation
			}
			newExec = v
		case a == "--workdir" || strings.HasPrefix(a, "--workdir="):
			v, ok := mcpFlagValue(argv, &i, "workdir")
			if !ok {
				return apperr.ExitCLIValidation
			}
			newWorkDir = v
		case a == "--env-file" || strings.HasPrefix(a, "--env-file="):
			v, ok := mcpFlagValue(argv, &i, "env-file")
			if !ok {
				return apperr.ExitCLIValidation
			}
			newEnvFile = v
		case a == "--auth" || strings.HasPrefix(a, "--auth="):
			v, ok := mcpFlagValue(argv, &i, "auth")
			if !ok {
				return apperr.ExitCLIValidation
			}
			if v != rec.Auth {
				fmt.Fprintf(os.Stderr, "cannot change authentication profile of %q from %q to %q in place; explicit migration or a new publication is required\n", name, rec.Auth, v)
				return apperr.ExitCLIValidation
			}
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
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	if _, kid, kerr := loadKeyForProfile(prof); kerr == nil {
		checkRelay := rec.RelayURL
		if newRelay != "" {
			checkRelay = newRelay
		}
		if err := verifyServiceIdentityOwnership(rec, kid, checkRelay); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitAuth
		}
	}
	if newExec != "" || newWorkDir != "" || newEnvFile != "" {
		normExec, normWD, normEnv, nerr := normalizeManagedBackendConfig(newExec, newWorkDir, newEnvFile)
		if nerr != nil {
			fmt.Fprintln(os.Stderr, nerr)
			return apperr.ExitCLIValidation
		}
		newExec, newWorkDir, newEnvFile = normExec, normWD, normEnv
	}
	updated, err := store.UpdateCAS(name, rec.Revision, func(r *config.ServiceRecord) error {
		targetChanged := false
		if newLocal != "" && newLocal != r.LocalURL {
			r.LocalURL = newLocal
			targetChanged = true
		}
		if newExec != "" && newExec != r.BackendExec {
			r.BackendExec = newExec
			targetChanged = true
		}
		if newWorkDir != "" && newWorkDir != r.BackendWorkDir {
			r.BackendWorkDir = newWorkDir
			targetChanged = true
		}
		if newEnvFile != "" && newEnvFile != r.BackendEnvFile {
			r.BackendEnvFile = newEnvFile
			targetChanged = true
		}
		if hasExecArgs {
			r.BackendArgs = newExecArgs
			targetChanged = true
		}
		if newRelay != "" && newRelay != r.RelayURL {
			r.RelayURL = newRelay
			targetChanged = true
		}
		if targetChanged {
			if r.ConfigGeneration <= 0 {
				r.ConfigGeneration = 1
			}
			r.ConfigGeneration++
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

func checkStartupGenerationCurrent(store *config.ServiceStore, name string, wantGen int64) (config.ServiceRecord, error) {
	fresh, ok, err := store.Get(name)
	if err != nil {
		return config.ServiceRecord{}, err
	}
	if !ok {
		return config.ServiceRecord{}, fmt.Errorf("service %q was removed during startup", name)
	}
	if fresh.DesiredState == config.DesiredDisabled {
		return fresh, fmt.Errorf("concurrent disable committed during startup for %q", name)
	}
	if fresh.StartupGeneration != wantGen {
		return fresh, fmt.Errorf("startup generation superseded for %q (%d != %d)", name, fresh.StartupGeneration, wantGen)
	}
	return fresh, nil
}

type serviceStartRequest struct {
	Name               string
	Foreground         bool
	WaitReady          bool
	RequirePersistence bool
}

type serviceStartOutcome struct {
	Record      config.ServiceRecord
	Status      ServiceStatusReport
	Persistence PersistenceVerification
}

// startHostedService executes the full service startup state machine without
// writing to stdout, so callers (`ocliv service start` vs `ocliv host --json`)
// own presentation strictly.
func startHostedService(req serviceStartRequest, ops serviceOps) (serviceStartOutcome, int, error) {
	var out serviceStartOutcome
	name := req.Name
	store, err := openServices()
	if err != nil {
		return out, apperr.ExitInternal, err
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		return out, apperr.ExitCLIValidation, fmt.Errorf("unknown service %q", name)
	}
	out.Record = rec
	// Bind credentials strictly to the profile the service was created with.
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	k, keyID, err := loadKeyForProfile(prof)
	if err != nil {
		return out, apperr.ExitAuth, fmt.Errorf("not enrolled in profile %q: run `ocliv login` first", prof)
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(prof)
	}
	if _, rerr := validateRelayTarget(relayURL); rerr != nil {
		return out, apperr.ExitCLIValidation, fmt.Errorf("service start: %w", rerr)
	}
	if oerr := verifyServiceIdentityOwnership(rec, keyID, relayURL); oerr != nil {
		return out, apperr.ExitAuth, fmt.Errorf("service start: %w", oerr)
	}

	if req.Foreground {
		if err := validateIdentitySchemaVersion(rec); err != nil {
			return out, apperr.ExitAuth, fmt.Errorf("service start: %w", err)
		}
		if identityNeedsBinding(rec) {
			migrated, merr := migrateLegacyServiceIdentity(store, rec, k, keyID, relayURL, ops)
			if merr != nil {
				return out, apperr.ExitAuth, fmt.Errorf("service start: %w", merr)
			}
			rec = migrated
		}
		if rec.PublicationID != "" {
			st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+rec.PublicationID+"/enable")
			if callErr != nil {
				return out, apperr.ExitRelayTLS, fmt.Errorf("service start: relay enable failed: %w", callErr)
			}
			if st != http.StatusOK && st != http.StatusNotFound {
				return out, apperr.ExitAuth, fmt.Errorf("service start: relay enable returned %d: %s", st, strings.TrimSpace(string(body)))
			}
		}
		if _, err := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.DesiredState = config.DesiredEnabled
			r.StartupGeneration++
			r.LastRecoveryAction = ""
			return nil
		}); err != nil {
			return out, apperr.ExitInternal, err
		}
		return out, startServiceForeground(rec), nil
	}

	fence := serviceFence(name)
	fence.Lock()
	defer fence.Unlock()

	// Re-read under fence for CAS accuracy.
	rec, ok, err = store.Get(name)
	if err != nil || !ok {
		return out, apperr.ExitCLIValidation, fmt.Errorf("unknown service %q", name)
	}

	// Explicit legacy/incomplete identity binding: prove authenticated ownership
	// before binding missing HostedServiceIdentity fields, and reject future schemas.
	if err := validateIdentitySchemaVersion(rec); err != nil {
		return out, apperr.ExitAuth, fmt.Errorf("service start: %w", err)
	}
	if identityNeedsBinding(rec) {
		migrated, merr := migrateLegacyServiceIdentity(store, rec, k, keyID, relayURL, ops)
		if merr != nil {
			return out, apperr.ExitAuth, fmt.Errorf("service start: %w", merr)
		}
		rec = migrated
	}
	if oerr := verifyServiceIdentityOwnership(rec, keyID, relayURL); oerr != nil {
		return out, apperr.ExitAuth, fmt.Errorf("service start: %w", oerr)
	}
	out.Record = rec

	// 1. Provision user-level supervisor units & 0600 env file.
	if ops.provision != nil {
		if perr := ops.provision(rec, ops); perr != nil {
			_, _ = store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
				r.LastFailure = perr.Error()
				return nil
			})
			return out, apperr.ExitInternal, fmt.Errorf("service start: supervisor provisioning failed: %w", perr)
		}
	}

	// 2. Persist a durable startup transition with a monotonic generation BEFORE
	//    launching any managed backend, so cmdServiceRunBackend only runs for an
	//    authorized startup transition and concurrent disable can fence it.
	prevDesired := rec.DesiredState
	startedRec, err := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
		if r.DesiredState != config.DesiredEnabled {
			r.DesiredState = config.DesiredStarting
		}
		r.StartupGeneration++
		r.LastFailure = ""
		r.LastRecoveryAction = ""
		return nil
	})
	if err != nil {
		return out, apperr.ExitInternal, err
	}
	rec = startedRec
	out.Record = rec
	startGen := rec.StartupGeneration

	rollbackStartup := func(failMsg, recovery string, stopBackend, disableRemote bool) {
		if stopBackend && rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
			_, _ = ops.systemctl("stop", rec.BackendUnit)
		}
		if disableRemote && prevDesired != config.DesiredEnabled && rec.PublicationID != "" {
			_, _, _ = ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+rec.PublicationID+"/disable")
		}
		_, _ = store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
			// Never overwrite a concurrent explicit disable.
			if r.DesiredState != config.DesiredDisabled && r.StartupGeneration == startGen && prevDesired != config.DesiredEnabled {
				r.DesiredState = prevDesired
			}
			r.LastFailure = failMsg
			if recovery != "" {
				r.LastRecoveryAction = recovery
			}
			return nil
		})
	}

	// 3. If managed backend, enable and start it under the active startup generation.
	backendStartedByUs := false
	if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		if outStr, berr := ops.systemctl("enable", rec.BackendUnit); berr != nil {
			if req.RequirePersistence {
				msg := fmt.Sprintf("could not enable backend unit %s for reboot persistence: %v (%s)", rec.BackendUnit, berr, strings.TrimSpace(outStr))
				rollbackStartup(msg, "verify systemd user session and retry", false, false)
				return out, apperr.ExitInternal, fmt.Errorf("service start: %s", msg)
			}
			fmt.Fprintf(os.Stderr, "warning: could not enable backend unit %s for reboot persistence: %v (%s)\n", rec.BackendUnit, berr, strings.TrimSpace(outStr))
		}
		if outStr, berr := ops.systemctl("start", rec.BackendUnit); berr != nil {
			msg := fmt.Sprintf("managed backend %s failed: %v (%s)", rec.BackendUnit, berr, strings.TrimSpace(outStr))
			rollbackStartup(msg, "check `systemctl --user status "+rec.BackendUnit+"` and retry", false, false)
			return out, apperr.ExitLocalTarget, fmt.Errorf("service start: %s", msg)
		}
		backendStartedByUs = true
	}

	// 4. Validate local backend reachability before mutating relay state.
	if len(rec.StdioCmd) == 0 {
		target, _, err := localTargetFromURL(rec.LocalURL)
		if err != nil {
			rollbackStartup(err.Error(), "", backendStartedByUs, false)
			return out, apperr.ExitCLIValidation, err
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
			if _, gerr := checkStartupGenerationCurrent(store, name, startGen); gerr != nil {
				rollbackStartup(gerr.Error(), "", backendStartedByUs, false)
				return out, apperr.ExitAuth, fmt.Errorf("service start: %w", gerr)
			}
			time.Sleep(250 * time.Millisecond)
		}
		if perr != nil {
			msg := fmt.Sprintf("local backend unreachable at %s: %v", target, perr)
			rollbackStartup(msg, "ensure the local backend is listening and retry `ocliv service start "+name+"`", backendStartedByUs, false)
			return out, apperr.ExitLocalTarget, fmt.Errorf("service start: %s", msg)
		}
	}

	// 5. Recheck startup generation BEFORE mutating remote publication state.
	freshRec, gerr := checkStartupGenerationCurrent(store, name, startGen)
	if gerr != nil {
		if backendStartedByUs && rec.BackendUnit != "" {
			_, _ = ops.systemctl("stop", rec.BackendUnit)
		}
		return out, apperr.ExitAuth, fmt.Errorf("service start: %w", gerr)
	}
	rec = freshRec

	// 6. Enable publication on relay if it already exists.
	if rec.PublicationID != "" {
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+rec.PublicationID+"/enable")
		if callErr != nil {
			msg := fmt.Sprintf("relay enable failed: %v", callErr)
			rollbackStartup(msg, "check relay connectivity and retry", backendStartedByUs, false)
			return out, apperr.ExitRelayTLS, fmt.Errorf("service start: %s", msg)
		}
		if st != http.StatusOK && st != http.StatusNotFound {
			msg := fmt.Sprintf("relay enable returned %d: %s", st, strings.TrimSpace(string(body)))
			rollbackStartup(msg, "", backendStartedByUs, false)
			return out, apperr.ExitAuth, fmt.Errorf("service start: %s", msg)
		}
	}

	// 7. Commit DesiredEnabled via CAS, fenced on StartupGeneration and non-disabled state.
	updated, err := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
		if r.DesiredState == config.DesiredDisabled {
			return fmt.Errorf("concurrent disable committed during startup for %q", name)
		}
		if r.StartupGeneration != startGen {
			return fmt.Errorf("startup generation superseded for %q", name)
		}
		r.DesiredState = config.DesiredEnabled
		r.LastRecoveryAction = ""
		return nil
	})
	if err != nil {
		if backendStartedByUs && rec.BackendUnit != "" {
			_, _ = ops.systemctl("stop", rec.BackendUnit)
		}
		if prevDesired != config.DesiredEnabled && rec.PublicationID != "" {
			_, _, _ = ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+rec.PublicationID+"/disable")
		}
		return out, apperr.ExitAuth, err
	}
	rec = updated
	out.Record = rec

	// 8. Enable publisher for persistence and verify configuration when requested.
	if outStr, eerr := ops.systemctl("enable", rec.SystemdUnit); eerr != nil {
		if req.RequirePersistence {
			msg := fmt.Sprintf("could not enable publisher unit %s for reboot persistence: %v (%s)", rec.SystemdUnit, eerr, strings.TrimSpace(outStr))
			rollbackStartup(msg, "verify systemd user session and retry", backendStartedByUs, true)
			return out, apperr.ExitInternal, fmt.Errorf("service start: %s", msg)
		}
		fmt.Fprintf(os.Stderr, "warning: could not enable publisher unit %s for reboot persistence: %v (%s)\n", rec.SystemdUnit, eerr, strings.TrimSpace(outStr))
	}
	if req.RequirePersistence {
		pv := verifyRebootPersistence(rec, ops)
		out.Persistence = pv
		if !pv.PersistenceConfigured {
			rollbackStartup("persistence configuration check failed: "+pv.FailureReason, "fix persistence prerequisites and retry", backendStartedByUs, true)
			return out, apperr.ExitInternal, fmt.Errorf("service start: persistence configuration check failed: %s", pv.FailureReason)
		}
	} else if u := strings.TrimSpace(os.Getenv("USER")); u != "" {
		if lout, lerr := runLoginctl(ops, "show-user", u, "-p", "Linger", "--value"); lerr == nil {
			if strings.TrimSpace(lout) == "no" {
				if _, eerr := runLoginctl(ops, "enable-linger", u); eerr != nil {
					fmt.Fprintf(os.Stderr, "warning: systemd user lingering is disabled for %q; service will stop on logout unless you run `sudo loginctl enable-linger %s`\n", u, u)
				}
			}
		}
	}

	// 9. Start (or controlled-restart if ConfigGeneration advanced on an active unit)
	//    the publisher unit; on failure roll back desired state.
	needRebindRestart := rec.ConfigGeneration > rec.AppliedConfigGeneration &&
		inspectUnit(rec.SystemdUnit, ops).ActiveState == "active"
	if needRebindRestart && rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		_, _ = ops.systemctl("restart", rec.BackendUnit)
	}
	startAction := "start"
	if needRebindRestart {
		startAction = "restart"
	}
	if outStr, err := ops.systemctl(startAction, rec.SystemdUnit); err != nil {
		msg := fmt.Sprintf("systemd %s %s failed: %v (%s)", startAction, rec.SystemdUnit, err, outStr)
		rollbackStartup(msg, "run `ocliv service start "+name+" --foreground` or check `systemctl --user status "+rec.SystemdUnit+"`", backendStartedByUs, true)
		return out, apperr.ExitInternal, fmt.Errorf("service start: %s", msg)
	}

	// 10. Verify readiness (bounded poll so unit has time to register and bind).
	var rep ServiceStatusReport
	for attempt := 0; attempt < 15; attempt++ {
		rep = inspectServiceStatus(rec, k, keyID, ops)
		if rep.State == ServiceStateServing || rep.State == ServiceStateFaulted || rep.State == ServiceStateRevoked {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	out.Status = rep
	if finalRec, uerr := store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
		if rep.PublicationID != "" {
			r.PublicationID = rep.PublicationID
			if r.Identity != nil {
				r.Identity.PublicationID = rep.PublicationID
			}
		}
		if rep.LeaseID != "" {
			r.LeaseID = rep.LeaseID
		}
		if rep.PublicURL != "" {
			r.PublicURL = rep.PublicURL
		}
		if rep.StateGeneration > 0 {
			r.StateGeneration = rep.StateGeneration
		}
		if rep.State == ServiceStateServing {
			if r.ConfigGeneration <= 0 {
				r.ConfigGeneration = 1
			}
			r.AppliedConfigGeneration = r.ConfigGeneration
			r.LastVerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
			r.LastFailure = ""
		}
		return nil
	}); uerr == nil {
		out.Record = finalRec
	}

	if rep.State == ServiceStateServing || (!req.WaitReady && rep.State == ServiceStateStarting) {
		return out, apperr.ExitOK, nil
	}
	return out, apperr.ExitInternal, fmt.Errorf("service %q did not reach serving state (state=%s health=%s)", rec.Name, rep.State, rep.Health)
}

func cmdServiceStart(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service start NAME [--foreground] [--wait-ready] [--require-persistence]")
		return apperr.ExitCLIValidation
	}
	req := serviceStartRequest{Name: argv[0]}
	for _, a := range argv[1:] {
		switch a {
		case "--foreground":
			req.Foreground = true
		case "--wait-ready":
			req.WaitReady = true
		case "--require-persistence":
			req.RequirePersistence = true
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	out, code, err := startHostedService(req, ops)
	if err != nil {
		if out.Status.State != "" {
			fmt.Printf("✓ service %s state=%s health=%s", req.Name, out.Status.State, out.Status.Health)
			if out.Status.PublicURL != "" {
				fmt.Printf(" url=%s", out.Status.PublicURL)
			}
			fmt.Println()
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return code
	}
	if !req.Foreground {
		fmt.Printf("✓ service %s state=%s health=%s", req.Name, out.Status.State, out.Status.Health)
		if out.Status.PublicURL != "" {
			fmt.Printf(" url=%s", out.Status.PublicURL)
		}
		fmt.Println()
	}
	return code
}

func buildHTTPPublisherArgs(rec config.ServiceRecord) ([]string, error) {
	target, _, err := localTargetFromURL(rec.LocalURL)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || port == "" {
		return nil, fmt.Errorf("invalid local HTTP target %q: missing port", rec.LocalURL)
	}
	args := []string{port, "--name", canonicalHTTPLabel(rec.Name), "--persistent"}
	if host != "" && host != "127.0.0.1" && host != "localhost" {
		args = append(args, "--upstream-host", host)
	}
	if rec.RelayURL != "" {
		args = append(args, "--relay", rec.RelayURL)
	}
	if rec.Auth == "public" {
		args = append(args, "--public")
	}
	return args, nil
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
	args, err := buildHTTPPublisherArgs(rec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitCLIValidation
	}
	return cmdTunnel(args)
}

func cmdServiceRunPublisher(argv []string) int {
	var name, profile string
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--name" || strings.HasPrefix(argv[i], "--name=") {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				return apperr.ExitCLIValidation
			}
			name = v
		} else if argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile=") {
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		}
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv service run-publisher --name NAME [--profile PROFILE]")
		return apperr.ExitCLIValidation
	}
	if profile == "" {
		profile = config.ActiveProfile()
	}
	store, err := openServicesForProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q in profile %q\n", name, profile)
		return apperr.ExitCLIValidation
	}
	if rec.DesiredState != config.DesiredEnabled {
		fmt.Fprintf(os.Stderr, "service %q desired state is %q (must be enabled); refusing to publish\n", name, rec.DesiredState)
		return apperr.ExitAuth
	}
	if len(rec.StdioCmd) == 0 && rec.LocalURL == "" {
		fmt.Fprintf(os.Stderr, "service %q has neither stdio command nor local URL\n", name)
		return apperr.ExitCLIValidation
	}
	if k, keyID, kerr := loadKeyForProfile(profile); kerr == nil {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			// Give the foreground publisher time to complete its initial
			// tunnel attachment and persist its lease before periodic
			// reconciliation evaluates health (avoiding a T=0 self-restart).
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			_ = runServiceReconcilerLoop(ctx, store, name, k, keyID, defaultServiceOps(), 30*time.Second)
		}()
	}
	return startServiceForeground(rec)
}

func cmdServiceReconcile(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service reconcile NAME [--json]")
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
	rep, rerr := reconcileServiceOnce(store, name, k, keyID, ops, time.Now())
	if jsonOut {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("service=%s state=%s health=%s\n", rep.Name, rep.State, rep.Health)
	}
	if rerr != nil {
		fmt.Fprintln(os.Stderr, rerr)
		return apperr.ExitInternal
	}
	return apperr.ExitOK
}

// cmdServiceRunBackend executes a managed backend with exact argument
// boundaries via exec.CommandContext (never flattened through a shell).
func cmdServiceRunBackend(argv []string) int {
	var name, profile string
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--name" || strings.HasPrefix(argv[i], "--name=") {
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				return apperr.ExitCLIValidation
			}
			name = v
		} else if argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile=") {
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		}
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv service run-backend --name NAME [--profile PROFILE]")
		return apperr.ExitCLIValidation
	}
	if profile == "" {
		profile = config.ActiveProfile()
	}
	store, err := openServicesForProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "unknown service %q in profile %q\n", name, profile)
		return apperr.ExitCLIValidation
	}
	if rec.BackendMode != config.BackendManaged || rec.BackendExec == "" {
		fmt.Fprintf(os.Stderr, "service %q is not a managed backend\n", name)
		return apperr.ExitCLIValidation
	}
	allowedToRun := rec.DesiredState == config.DesiredEnabled ||
		(rec.DesiredState == config.DesiredStarting && rec.StartupGeneration > 0)
	if !allowedToRun {
		fmt.Fprintf(os.Stderr, "service %q desired state is %q (must be enabled or starting with valid generation); refusing to start managed backend\n", name, rec.DesiredState)
		return apperr.ExitAuth
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd := exec.CommandContext(ctx, rec.BackendExec, rec.BackendArgs...)
	if rec.BackendWorkDir != "" {
		cmd.Dir = rec.BackendWorkDir
	}
	if rec.BackendEnvFile != "" {
		env, eerr := loadBackendEnvFileStrict(rec.BackendEnvFile, os.Environ())
		if eerr != nil {
			// P1-11: configured env-file is REQUIRED; fail closed if missing/unreadable/malformed.
			fmt.Fprintln(os.Stderr, "backend env-file error: "+eerr.Error())
			return apperr.ExitCLIValidation
		}
		cmd.Env = env
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			// Intentional shutdown via SIGTERM/SIGINT from systemd or operator.
			return apperr.ExitOK
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	return apperr.ExitOK
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
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service disable NAME [--json]")
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
	} else {
		fmt.Printf("service=%s remote_disable_status=%s local_stopped=%v state=%s detail=%s\n", res.Name, res.RemoteDisableStatus, res.LocalStopped, res.State, res.Detail)
	}
	if rec.Type == "http" && res.RemoteDisableStatus == "NEVER_PUBLISHED" {
		if !res.LocalStopped {
			return apperr.ExitInternal
		}
		return apperr.ExitOK
	}
	if !res.RemoteDisabled {
		return apperr.ExitRelayTLS
	}
	return apperr.ExitOK
}

// restartHostedService performs a non-destructive rebind/restart: it keeps
// DesiredState enabled and preserves ServiceID, HTTP hostname/visitor sessions,
// and MCP PublicationID/PublicURL without invoking the destructive stop/revoke path.
func restartHostedService(name string, ops serviceOps) (serviceStartOutcome, int, error) {
	return restartHostedServiceInProfile(config.ActiveProfile(), name, ops)
}

func restartHostedServiceInProfile(profile, name string, ops serviceOps) (serviceStartOutcome, int, error) {
	var out serviceStartOutcome
	store, err := openServicesForProfile(profile)
	if err != nil {
		return out, apperr.ExitInternal, err
	}
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		return out, apperr.ExitCLIValidation, fmt.Errorf("unknown service %q", name)
	}
	if rec.DesiredState != config.DesiredEnabled {
		return startHostedService(serviceStartRequest{Name: name, WaitReady: true}, ops)
	}
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	k, keyID, err := loadKeyForProfile(prof)
	if err != nil {
		return out, apperr.ExitAuth, fmt.Errorf("not enrolled in profile %q: run `ocliv login` first", prof)
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(prof)
	}
	if err := validateIdentitySchemaVersion(rec); err != nil {
		return out, apperr.ExitAuth, err
	}
	if err := verifyServiceIdentityOwnership(rec, keyID, relayURL); err != nil {
		return out, apperr.ExitAuth, err
	}
	if identityNeedsBinding(rec) {
		migrated, merr := migrateLegacyServiceIdentity(store, rec, k, keyID, relayURL, ops)
		if merr != nil {
			return out, apperr.ExitAuth, merr
		}
		rec = migrated
	}

	fence := serviceFence(name)
	fence.Lock()
	defer fence.Unlock()

	if ops.provision != nil {
		if perr := ops.provision(rec, ops); perr != nil {
			return out, apperr.ExitInternal, fmt.Errorf("service restart: supervisor provisioning failed: %w", perr)
		}
	}
	// Fence every systemd side effect against concurrent stop/disable across processes.
	checkStillEnabled := func() error {
		fresh, fok, ferr := store.Get(name)
		if ferr != nil || !fok || fresh.DesiredState != config.DesiredEnabled {
			return fmt.Errorf("concurrent stop/disable committed during restart for %q", name)
		}
		return nil
	}
	if err := checkStillEnabled(); err != nil {
		return out, apperr.ExitAuth, err
	}
	if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		if outStr, berr := ops.systemctl("restart", rec.BackendUnit); berr != nil {
			return out, apperr.ExitLocalTarget, fmt.Errorf("service restart: backend %s failed: %v (%s)", rec.BackendUnit, berr, strings.TrimSpace(outStr))
		}
		if err := checkStillEnabled(); err != nil {
			_, _ = ops.systemctl("stop", rec.BackendUnit)
			return out, apperr.ExitAuth, err
		}
	}
	if len(rec.StdioCmd) == 0 && ops.probeLoc != nil {
		target, _, lerr := localTargetFromURL(rec.LocalURL)
		if lerr != nil {
			return out, apperr.ExitCLIValidation, lerr
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
			if err := checkStillEnabled(); err != nil {
				if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
					_, _ = ops.systemctl("stop", rec.BackendUnit)
				}
				return out, apperr.ExitAuth, err
			}
			time.Sleep(250 * time.Millisecond)
		}
		if perr != nil {
			return out, apperr.ExitLocalTarget, fmt.Errorf("service restart: local backend unreachable at %s: %w", target, perr)
		}
	}
	if err := checkStillEnabled(); err != nil {
		if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
			_, _ = ops.systemctl("stop", rec.BackendUnit)
		}
		return out, apperr.ExitAuth, err
	}
	if outStr, serr := ops.systemctl("restart", rec.SystemdUnit); serr != nil {
		return out, apperr.ExitInternal, fmt.Errorf("service restart: systemd restart %s failed: %v (%s)", rec.SystemdUnit, serr, strings.TrimSpace(outStr))
	}
	if err := checkStillEnabled(); err != nil {
		_, _ = ops.systemctl("stop", rec.SystemdUnit)
		if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
			_, _ = ops.systemctl("stop", rec.BackendUnit)
		}
		return out, apperr.ExitAuth, err
	}
	var rep ServiceStatusReport
	for attempt := 0; attempt < 15; attempt++ {
		rep = inspectServiceStatus(rec, k, keyID, ops)
		if rep.State == ServiceStateServing || rep.State == ServiceStateFaulted || rep.State == ServiceStateRevoked {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	out.Status = rep
	if finalRec, uerr := store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
		if rep.PublicationID != "" {
			r.PublicationID = rep.PublicationID
			if r.Identity != nil {
				r.Identity.PublicationID = rep.PublicationID
			}
		}
		if rep.LeaseID != "" {
			r.LeaseID = rep.LeaseID
		}
		if rep.PublicURL != "" {
			r.PublicURL = rep.PublicURL
		}
		if rep.StateGeneration > 0 {
			r.StateGeneration = rep.StateGeneration
		}
		if rep.State == ServiceStateServing {
			if r.ConfigGeneration <= 0 {
				r.ConfigGeneration = 1
			}
			r.AppliedConfigGeneration = r.ConfigGeneration
			r.LastVerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
			r.LastFailure = ""
		}
		return nil
	}); uerr == nil {
		out.Record = finalRec
	}
	if rep.State == ServiceStateServing {
		return out, apperr.ExitOK, nil
	}
	return out, apperr.ExitInternal, fmt.Errorf("service %q did not return to serving state after restart (state=%s health=%s)", rec.Name, rep.State, rep.Health)
}

func cmdServiceRestart(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service restart NAME")
		return apperr.ExitCLIValidation
	}
	out, code, err := restartHostedService(argv[0], ops)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return code
	}
	fmt.Printf("✓ restarted service %s state=%s health=%s", argv[0], out.Status.State, out.Status.Health)
	if out.Status.PublicURL != "" {
		fmt.Printf(" url=%s", out.Status.PublicURL)
	}
	fmt.Println()
	return apperr.ExitOK
}

// cmdServiceLogs streams or prints systemd user journal logs for a hosted service.
func cmdServiceLogs(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv logs NAME [-f|--follow] [--lines N] [--backend]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	follow := false
	backend := false
	lines := "100"
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-f" || a == "--follow":
			follow = true
		case a == "--backend":
			backend = true
		case a == "--lines" || strings.HasPrefix(a, "--lines="):
			v, ok := mcpFlagValue(argv, &i, "lines")
			if !ok {
				return apperr.ExitCLIValidation
			}
			if _, err := strconv.Atoi(v); err != nil {
				fmt.Fprintf(os.Stderr, "invalid --lines %q\n", v)
				return apperr.ExitCLIValidation
			}
			lines = v
		default:
			fmt.Fprintf(os.Stderr, "unknown logs flag %q\n", a)
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
	unit := rec.SystemdUnit
	if backend {
		if rec.BackendUnit == "" {
			fmt.Fprintf(os.Stderr, "service %q does not have a managed backend unit\n", name)
			return apperr.ExitCLIValidation
		}
		unit = rec.BackendUnit
	}
	jargs := []string{"--user", "-u", unit, "-n", lines, "--no-pager"}
	if follow {
		jargs = append(jargs, "-f")
	}
	cmd := exec.Command("journalctl", jargs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "journalctl failed: %v\n", err)
		return apperr.ExitInternal
	}
	return apperr.ExitOK
}

func cmdServiceStatus(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv service status NAME [--json] [--strict-health]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	jsonOut := false
	strictHealth := false
	for _, a := range argv[1:] {
		if a == "--json" {
			jsonOut = true
		} else if a == "--strict-health" {
			strictHealth = true
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
	case HealthDegraded:
		if strictHealth {
			return apperr.ExitInternal
		}
		return apperr.ExitOK
	default:
		if strictHealth {
			return apperr.ExitInternal
		}
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
		fmt.Fprintln(os.Stderr, "usage: ocliv remove NAME [--yes | --confirm NAME] [--forget-local]")
		return apperr.ExitCLIValidation
	}
	name := argv[0]
	var confirm string
	var forgetLocal, yes bool
	for i := 1; i < len(argv); i++ {
		if argv[i] == "--confirm" || strings.HasPrefix(argv[i], "--confirm=") {
			v, ok := mcpFlagValue(argv, &i, "confirm")
			if !ok {
				return apperr.ExitCLIValidation
			}
			confirm = v
		} else if argv[i] == "--yes" || argv[i] == "-y" {
			yes = true
		} else if argv[i] == "--forget-local" {
			forgetLocal = true
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if !yes && confirm != name {
		if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
			fmt.Fprintf(os.Stderr, "Permanently remove service %q and revoke its public route? [y/N] ", name)
			var answer string
			_, _ = fmt.Fscanln(os.Stdin, &answer)
			answer = strings.ToLower(strings.TrimSpace(answer))
			if answer != "y" && answer != "yes" {
				fmt.Fprintln(os.Stderr, "aborted")
				return apperr.ExitCLIValidation
			}
		} else {
			fmt.Fprintf(os.Stderr, "permanent removal requires `--yes` or `--confirm %s`\n", name)
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
	if forgetLocal {
		if err := forgetLocalService(store, rec, ops); err != nil {
			fmt.Fprintf(os.Stderr, "service remove --forget-local: %v\n", err)
			return apperr.ExitInternal
		}
		fmt.Printf("✓ forgot local service %s (remote route, if any, was not modified)\n", name)
		return apperr.ExitOK
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
		path = "/v1/agent/mcp-routes/" + pubID + "/authz/approve-direct/" + clientID
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
