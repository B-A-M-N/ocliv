package cli

import (
	"crypto/sha256"
	"encoding/hex"
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
// (<profile>--<service-name>-<hash6>) so services with the same name in
// different profiles or containing "--" never collide on unit names or env files.
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
	sum := sha256.Sum256([]byte(prof + "\x00" + name))
	return prof + "--" + name + "-" + hex.EncodeToString(sum[:3]), nil
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
	Enabled          bool   `json:"enabled,omitempty"`
	EnabledKnown     bool   `json:"enabled_known"`
	EnabledState     string `json:"enabled_state,omitempty"`
	Error            string `json:"error,omitempty"`
}

func inspectUnit(unit string, ops serviceOps) UnitInspection {
	if unit == "" {
		return UnitInspection{ManagerReachable: true, ActiveState: "not-configured", EnabledKnown: true, EnabledState: "not-configured"}
	}
	loadState, lerr := ops.systemctl("show", "-p", "LoadState", "--value", unit)
	ls := strings.TrimSpace(loadState)
	if lerr != nil && (strings.Contains(ls, "Failed to connect") || strings.Contains(lerr.Error(), "Failed to connect")) {
		return UnitInspection{ManagerReachable: false, ActiveState: "manager-unreachable", EnabledState: "enabled-unknown", Error: ls}
	}
	if lerr == nil && ls == "not-found" {
		return UnitInspection{ManagerReachable: true, LoadState: "not-found", ActiveState: "not-found", EnabledKnown: true, EnabledState: "not-found"}
	}
	enabled := false
	enabledKnown := false
	enabledState := "enabled-unknown"
	enOut, eerr := ops.systemctl("is-enabled", unit)
	en := strings.TrimSpace(enOut)
	if eerr != nil && (strings.Contains(en, "Failed to connect") || strings.Contains(eerr.Error(), "Failed to connect")) {
		return UnitInspection{ManagerReachable: false, LoadState: ls, ActiveState: "manager-unreachable", EnabledState: "enabled-unknown", Error: en}
	}
	switch en {
	case "enabled", "enabled-runtime", "static", "indirect":
		enabled = true
		enabledKnown = true
		enabledState = en
	case "disabled", "masked", "not-found":
		enabled = false
		enabledKnown = true
		enabledState = en
	default:
		if eerr == nil && en != "" {
			enabledState = en
		}
	}
	act, aerr := ops.systemctl("is-active", unit)
	act = strings.TrimSpace(act)
	if aerr != nil && (strings.Contains(act, "Failed to connect") || strings.Contains(aerr.Error(), "Failed to connect")) {
		return UnitInspection{ManagerReachable: false, LoadState: ls, ActiveState: "manager-unreachable", Enabled: enabled, EnabledKnown: enabledKnown, EnabledState: enabledState, Error: act}
	}
	switch act {
	case "active", "activating", "deactivating", "reloading", "inactive", "failed", "not-found":
		return UnitInspection{ManagerReachable: true, LoadState: ls, ActiveState: act, Enabled: enabled, EnabledKnown: enabledKnown, EnabledState: enabledState}
	}
	errMsg := "unknown active state"
	if aerr != nil {
		errMsg = aerr.Error()
	}
	return UnitInspection{ManagerReachable: true, LoadState: ls, ActiveState: "unknown", Enabled: enabled, EnabledKnown: enabledKnown, EnabledState: enabledState, Error: errMsg}
}

// queryUnitState distinguishes "not-found", "active", "activating", "failed",
// "inactive", and "manager-unreachable".
func queryUnitState(unit string, ops serviceOps) string {
	return inspectUnit(unit, ops).ActiveState
}

// UnitStopEvidence records authoritative systemd stop and disable proof so
// local service records are never removed while a unit is active, enabled,
// or unreachable.
type UnitStopEvidence struct {
	Unit              string `json:"unit"`
	ActiveState       string `json:"active_state"`
	StoppedNow        bool   `json:"stopped_now"`
	DisabledForReboot bool   `json:"disabled_for_reboot"`
	Error             string `json:"error,omitempty"`
}

func stopAndVerifyUnit(unit string, disable bool, ops serviceOps) UnitStopEvidence {
	ev := UnitStopEvidence{Unit: unit}
	if unit == "" {
		ev.ActiveState = "not-configured"
		ev.StoppedNow = true
		ev.DisabledForReboot = true
		return ev
	}
	before := inspectUnit(unit, ops)
	ev.ActiveState = before.ActiveState
	if !before.ManagerReachable {
		ev.Error = "STOP_UNCONFIRMED: systemd manager unreachable (" + before.Error + ")"
		return ev
	}
	if before.ActiveState == "not-found" {
		ev.StoppedNow = true
		ev.DisabledForReboot = true
		return ev
	}
	if out, err := ops.systemctl("stop", unit); err != nil {
		ev.Error = fmt.Sprintf("systemctl stop %s failed: %v (%s)", unit, err, strings.TrimSpace(out))
	}
	after := inspectUnit(unit, ops)
	ev.ActiveState = after.ActiveState
	if !after.ManagerReachable {
		ev.Error = "STOP_UNCONFIRMED: systemd manager became unreachable after stop"
		return ev
	}
	switch after.ActiveState {
	case "inactive", "failed", "not-found":
		ev.StoppedNow = true
	default:
		if ev.Error == "" {
			ev.Error = fmt.Sprintf("STOP_UNCONFIRMED: unit %s is %s", unit, after.ActiveState)
		}
	}
	if !disable {
		ev.DisabledForReboot = after.EnabledKnown && !after.Enabled
		return ev
	}
	if out, derr := ops.systemctl("disable", unit); derr != nil {
		afterDis := inspectUnit(unit, ops)
		if afterDis.ManagerReachable && afterDis.ActiveState == "not-found" {
			ev.DisabledForReboot = true
			return ev
		}
		ev.DisabledForReboot = false
		if ev.Error == "" {
			ev.Error = fmt.Sprintf("STOP_UNCONFIRMED: systemctl disable %s failed: %v (%s)", unit, derr, strings.TrimSpace(out))
		}
		return ev
	}
	afterDis := inspectUnit(unit, ops)
	if !afterDis.ManagerReachable || !afterDis.EnabledKnown || afterDis.Enabled {
		ev.DisabledForReboot = false
		if ev.Error == "" {
			ev.Error = fmt.Sprintf("STOP_UNCONFIRMED: unit %s enabled state after disable is %s", unit, afterDis.EnabledState)
		}
		return ev
	}
	ev.DisabledForReboot = true
	return ev
}
