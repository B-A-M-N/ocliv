package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ManagedMarker tags files ocliv setup owns. An existing destination
// without the marker is treated as unrelated (possibly another
// application's config) and is never overwritten automatically.
const ManagedMarker = "# managed by ocliv setup"

// runCaddyValidate and runDaemonReload are indirection points so
// install/rollback behavior is testable without a live Caddy or
// systemd.
var runCaddyValidate = func(dst string) error {
	return runCmd("caddy", "validate", "--config", dst, "--adapter", "caddyfile")
}
var runDaemonReload = func() error {
	return runCmd("systemctl", "daemon-reload")
}

// Step is one bootstrap action. Auto steps run inside `setup --auto`
// (root only); manual steps print the exact command for the operator.
// Manual is always populated so automation never hides what it did.
type Step struct {
	Title  string
	Auto   bool
	Manual string
}

// BootstrapEnv is everything the planner may consider. It is gathered,
// not guessed: AsRoot from the process euid, CaddyPresent from PATH.
type BootstrapEnv struct {
	AsRoot       bool
	CaddyPresent bool
	Path         Path
	Hostname     string
	DeployDir    string
}

// PlanBootstrap returns the edge-provisioning steps for a viable path,
// or a block reason when no viable public path exists. CGNAT and
// unknown paths never produce steps: running ACME against an
// unreachable edge can only fail loudly later, so refuse early with
// the precise cause.
func PlanBootstrap(env BootstrapEnv) (steps []Step, blockReason string) {
	switch env.Path {
	case PathDirectV6, PathDirectV4, PathNATV4:
		// viable: direct now, or after the router forward
	default:
		return nil, "no viable direct path (" + env.Path.String() + "): resolve the cause in `setup --check`, then re-run"
	}
	if !env.CaddyPresent {
		return []Step{{
			Title:  "install Caddy",
			Manual: "install Caddy from https://caddyserver.com/docs/install (apt/dnf/docker), then re-run `ocliv setup --auto`",
		}}, "re-run after installing Caddy"
	}
	caddyDst := "/etc/caddy/Caddyfile"
	unitDst := "/etc/systemd/system/ocliv-relay.service"
	mk := func(title, manual string) Step {
		return Step{Title: title, Auto: env.AsRoot, Manual: manual}
	}
	steps = []Step{
		mk("install Caddyfile",
			fmt.Sprintf("cp %s %s && caddy validate --config %s --adapter caddyfile",
				filepath.Join(env.DeployDir, "Caddyfile"), caddyDst, caddyDst)),
		mk("install systemd unit",
			fmt.Sprintf("cp %s %s && systemctl daemon-reload",
				filepath.Join(env.DeployDir, "ocliv-relay.service"), unitDst)),
		mk("enable and start relay",
			"systemctl enable --now ocliv-relay && systemctl is-active ocliv-relay"),
		mk("enroll this machine",
			fmt.Sprintf("ocliv relay issue-enroll --data /var/lib/ocliv --tenant home && ocliv login --relay https://%s --code-file -", env.Hostname)),
	}
	return steps, ""
}

// runCmd executes a system command for the live executors below.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, string(out))
	}
	return nil
}

// InstallCaddyfile installs the rendered edge config with ownership
// checks and rollback (see installManagedFile).
func InstallCaddyfile(deployDir string) error {
	return InstallCaddyfileTo(deployDir, "/etc/caddy/Caddyfile")
}

// InstallCaddyfileTo is InstallCaddyfile with an explicit
// destination so install/rollback behavior is testable without
// touching /etc.
func InstallCaddyfileTo(deployDir, dst string) error {
	raw, err := os.ReadFile(filepath.Join(deployDir, "Caddyfile"))
	if err != nil {
		return err
	}
	return installManagedFile(dst, raw, func(dst string) error {
		return runCaddyValidate(dst)
	})
}

// InstallUnit places the rendered systemd unit and reloads the
// manager. It starts nothing.
func InstallUnit(deployDir string) error {
	return InstallUnitTo(deployDir, "/etc/systemd/system/ocliv-relay.service")
}

// InstallUnitTo is InstallUnit with an explicit destination so
// install/rollback behavior is testable without touching /etc.
func InstallUnitTo(deployDir, dst string) error {
	raw, err := os.ReadFile(filepath.Join(deployDir, "ocliv-relay.service"))
	if err != nil {
		return err
	}
	if err := installManagedFile(dst, raw, func(string) error {
		return runDaemonReload()
	}); err != nil {
		return err
	}
	return nil
}

// installManagedFile stages a candidate config with clear ownership:
// an existing file without the ocliv marker is refused (it may
// belong to another application); a managed file is backed up, the
// candidate is written, and validation failure restores the backup.
// The backup remains until CleanInstallBackup runs after the whole
// operation succeeds, so a later step failure can still roll back.
func installManagedFile(dst string, candidate []byte, validate func(string) error) error {
	if prev, err := os.ReadFile(dst); err == nil {
		if !strings.Contains(string(prev), ManagedMarker) {
			return fmt.Errorf("refusing to overwrite unmanaged %s (no %q marker): back it up, move it aside, or adopt it by adding the marker line, then re-run", dst, ManagedMarker)
		}
		if err := os.WriteFile(dst+".ocliv-bak", prev, 0o644); err != nil {
			return fmt.Errorf("backing up %s: %w", dst, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", dst, err)
	}
	if err := os.WriteFile(dst, candidate, 0o644); err != nil {
		return fmt.Errorf("installing %s: %w", dst, err)
	}
	if err := validate(dst); err != nil {
		if prev, rerr := os.ReadFile(dst + ".ocliv-bak"); rerr == nil {
			_ = os.WriteFile(dst, prev, 0o644)
			_ = os.Remove(dst + ".ocliv-bak")
		} else {
			_ = os.Remove(dst)
		}
		return fmt.Errorf("validation failed, previous config restored: %w", err)
	}
	return nil
}

// RollbackInstalled restores the pre-install backup of one managed
// file after a later provisioning step fails. Best effort by design:
// it reports nothing when there is nothing to restore.
func RollbackInstalled(dst string) {
	if prev, err := os.ReadFile(dst + ".ocliv-bak"); err == nil {
		_ = os.WriteFile(dst, prev, 0o644)
		_ = os.Remove(dst + ".ocliv-bak")
	}
}

// CleanInstallBackup drops a consumed backup after the whole
// operation succeeds. Backups are never left behind a good install.
func CleanInstallBackup(dst string) {
	_ = os.Remove(dst + ".ocliv-bak")
}

// StartRelay enables and starts the relay, then reports the active
// state. Deeper liveness stays with relay doctor and the external
// verification step.
func StartRelay() error {
	if err := runCmd("systemctl", "enable", "--now", "ocliv-relay"); err != nil {
		return err
	}
	return runCmd("systemctl", "is-active", "ocliv-relay")
}
