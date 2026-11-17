package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"ocliv/internal/config"
)

const userPublisherUnitTemplate = `# User-level Ocliv service publisher (%i).
# Provisioned automatically by ` + "`ocliv service start`" + `.
[Unit]
Description=Ocliv user service publisher (%i)
After=network-online.target ocliv-backend@%i.service
Wants=ocliv-backend@%i.service

[Service]
Type=simple
EnvironmentFile=%h/.config/ocliv/service-%i.env
ExecStart=/bin/sh -c 'exec $${OCLIV_BIN} service run-publisher --name="$${OCLIV_NAME:-%i}" --profile="$${OCLIV_PROFILE:-default}"'
Restart=on-failure
RestartPreventExitStatus=2 4 6 7
RestartSec=15
KillSignal=SIGTERM
TimeoutStopSec=60
SuccessExitStatus=0

[Install]
WantedBy=default.target
`

const userBackendUnitTemplate = `# User-level Ocliv managed backend (%i).
# Provisioned automatically by ` + "`ocliv service start`" + ` for --manage services.
[Unit]
Description=Ocliv managed local backend (%i)

[Service]
Type=simple
EnvironmentFile=%h/.config/ocliv/service-%i.env
ExecStart=/bin/sh -c 'exec $${OCLIV_BIN} service run-backend --name="$${OCLIV_NAME:-%i}" --profile="$${OCLIV_PROFILE:-default}"'
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=default.target
`

func writeAtomic0600(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ocliv-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func userSystemdDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("cannot locate home directory for user systemd units")
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

func validUnitComponent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// serviceInstanceID returns the canonical systemd instance identity
// (<profile>--<service-name>) so services with the same name in different
// profiles never collide on unit names or environment files.
func serviceInstanceID(profile, name string) (string, error) {
	prof := strings.TrimSpace(profile)
	if prof == "" {
		prof = "default"
	}
	if !validUnitComponent(prof) {
		return "", fmt.Errorf("invalid profile name %q for systemd unit", prof)
	}
	if !validUnitComponent(name) {
		return "", fmt.Errorf("invalid service name %q for systemd unit", name)
	}
	return prof + "--" + name, nil
}

func serviceUnitInstance(rec config.ServiceRecord) (string, error) {
	if strings.HasPrefix(rec.SystemdUnit, "ocliv-publisher@") && strings.HasSuffix(rec.SystemdUnit, ".service") {
		inst := strings.TrimSuffix(strings.TrimPrefix(rec.SystemdUnit, "ocliv-publisher@"), ".service")
		if validUnitComponent(inst) {
			return inst, nil
		}
	}
	return serviceInstanceID(rec.Profile, rec.Name)
}

func serviceEnvPath(rec config.ServiceRecord) (string, error) {
	inst, err := serviceUnitInstance(rec)
	if err != nil {
		return "", err
	}
	home, herr := os.UserHomeDir()
	if herr == nil && home != "" {
		return filepath.Join(home, ".config", "ocliv", "service-"+inst+".env"), nil
	}
	dir, err := config.DataDirForProfile(rec.Profile)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "service-"+inst+".env"), nil
}

// sanitizeEnvValue rejects newlines/nulls so env-file writes cannot inject extra variables.
func sanitizeEnvValue(v string) (string, error) {
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", fmt.Errorf("unsafe control character in configuration value")
	}
	return v, nil
}

// provisionUserSupervisor validates the executable, target, and profile,
// writes the per-service 0600 env file (no bearer secrets), installs the
// user-level systemd unit templates, and reloads the user daemon.
func provisionUserSupervisor(rec config.ServiceRecord, ops serviceOps) error {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		if p, lerr := exec.LookPath("ocliv"); lerr == nil {
			exe = p
		} else {
			return fmt.Errorf("cannot locate ocliv executable: %w", err)
		}
	}
	if st, err := os.Stat(exe); err != nil || st.Mode()&0o111 == 0 {
		return fmt.Errorf("ocliv executable %q is not runnable", exe)
	}
	if rec.BackendMode == config.BackendManaged {
		if rec.BackendExec == "" {
			return fmt.Errorf("managed backend requires --exec")
		}
		bpath, berr := exec.LookPath(rec.BackendExec)
		if berr != nil {
			return fmt.Errorf("managed backend executable %q not found: %w", rec.BackendExec, berr)
		}
		if st, err := os.Stat(bpath); err != nil || st.Mode()&0o111 == 0 {
			return fmt.Errorf("managed backend executable %q is not executable", bpath)
		}
	}
	envPath, err := serviceEnvPath(rec)
	if err != nil {
		return err
	}
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	relay := rec.RelayURL
	if relay == "" {
		relay = agentRelayURLForProfile(prof)
	}
	fields := []struct{ k, v string }{
		{"OCLIV_BIN", exe},
		{"OCLIV_NAME", rec.Name},
		{"OCLIV_TYPE", rec.Type},
		{"OCLIV_AUTH", rec.Auth},
		{"OCLIV_PROFILE", prof},
		{"OCLIV_RELAY_URL", relay},
		{"OCLIV_LOCAL_URL", rec.LocalURL},
	}
	if rec.BackendMode == config.BackendManaged {
		fields = append(fields,
			struct{ k, v string }{"OCLIV_BACKEND_EXEC", rec.BackendExec},
			struct{ k, v string }{"OCLIV_BACKEND_ARGS", strings.Join(rec.BackendArgs, " ")},
		)
	}
	var sb strings.Builder
	sb.WriteString("# Managed by `ocliv service` (mode 0600; no bearer secrets).\n")
	for _, f := range fields {
		clean, cerr := sanitizeEnvValue(f.v)
		if cerr != nil {
			return fmt.Errorf("%s: %w", f.k, cerr)
		}
		sb.WriteString(f.k)
		sb.WriteByte('=')
		sb.WriteString(clean)
		sb.WriteByte('\n')
	}
	if err := writeAtomic0600(envPath, sb.String()); err != nil {
		return fmt.Errorf("writing service env file: %w", err)
	}

	unitDir, err := userSystemdDir()
	if err != nil {
		return err
	}
	pubUnit := filepath.Join(unitDir, "ocliv-publisher@.service")
	if err := writeAtomic0600(pubUnit, userPublisherUnitTemplate); err != nil {
		return fmt.Errorf("writing publisher unit template: %w", err)
	}
	if rec.BackendMode == config.BackendManaged {
		beUnit := filepath.Join(unitDir, "ocliv-backend@.service")
		if err := writeAtomic0600(beUnit, userBackendUnitTemplate); err != nil {
			return fmt.Errorf("writing backend unit template: %w", err)
		}
	}
	if out, err := ops.systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("systemctl --user daemon-reload failed: %v (%s)", err, out)
	}
	return nil
}

// UnitInspection holds structured systemd user unit state without leaking
// raw D-Bus/systemctl error strings as process states.
type UnitInspection struct {
	ManagerReachable bool   `json:"manager_reachable"`
	LoadState        string `json:"load_state,omitempty"`
	ActiveState      string `json:"active_state"`
	Error            string `json:"error,omitempty"`
}

func inspectUnit(unit string, ops serviceOps) UnitInspection {
	if unit == "" {
		return UnitInspection{ManagerReachable: true, ActiveState: "not-configured"}
	}
	loadState, lerr := ops.systemctl("show", "-p", "LoadState", "--value", unit)
	ls := strings.TrimSpace(loadState)
	if lerr != nil && (strings.Contains(ls, "Failed to connect") || strings.Contains(lerr.Error(), "Failed to connect")) {
		return UnitInspection{ManagerReachable: false, ActiveState: "manager-unreachable", Error: ls}
	}
	if lerr == nil && ls == "not-found" {
		return UnitInspection{ManagerReachable: true, LoadState: "not-found", ActiveState: "not-found"}
	}
	act, aerr := ops.systemctl("is-active", unit)
	act = strings.TrimSpace(act)
	if aerr != nil && (strings.Contains(act, "Failed to connect") || strings.Contains(aerr.Error(), "Failed to connect")) {
		return UnitInspection{ManagerReachable: false, LoadState: ls, ActiveState: "manager-unreachable", Error: act}
	}
	switch act {
	case "active", "activating", "deactivating", "reloading", "inactive", "failed", "not-found":
		return UnitInspection{ManagerReachable: true, LoadState: ls, ActiveState: act}
	}
	if aerr != nil {
		return UnitInspection{ManagerReachable: true, LoadState: ls, ActiveState: "inactive", Error: aerr.Error()}
	}
	return UnitInspection{ManagerReachable: true, LoadState: ls, ActiveState: "unknown"}
}

// queryUnitState distinguishes "not-found", "active", "activating", "failed",
// "inactive", and "manager-unreachable".
func queryUnitState(unit string, ops serviceOps) string {
	return inspectUnit(unit, ops).ActiveState
}
