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

// newFileSentinel marks a destination that did not exist before
// installation: the small explicit journal entry that lets a later
// step failure undo a newly created file instead of leaving a
// half-installed edge config behind.
func newFileSentinel(dst string) string { return dst + ".ocliv-new" }

// installManagedFile stages a candidate config with clear ownership:
// an existing file without the ocliv marker is refused (it may
// belong to another application); a managed file is backed up, the
// candidate is written, and validation failure restores the backup.
// A newly created destination is journaled with a sentinel so a
// later step failure can remove it. Backups and sentinels remain
// until CleanInstallBackup runs after the whole operation succeeds.
func installManagedFile(dst string, candidate []byte, validate func(string) error) error {
	existed := true
	if prev, err := os.ReadFile(dst); err == nil {
		if !strings.Contains(string(prev), ManagedMarker) {
			return fmt.Errorf("refusing to overwrite unmanaged %s (no %q marker): back it up, move it aside, or adopt it by adding the marker line, then re-run", dst, ManagedMarker)
		}
		if err := os.WriteFile(dst+".ocliv-bak", prev, 0o644); err != nil {
			return fmt.Errorf("backing up %s: %w", dst, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", dst, err)
	} else {
		existed = false
	}
	if err := os.WriteFile(dst, candidate, 0o644); err != nil {
		return fmt.Errorf("installing %s: %w", dst, err)
	}
	if err := validate(dst); err != nil {
		if prev, rerr := os.ReadFile(dst + ".ocliv-bak"); rerr == nil {
			_ = os.WriteFile(dst, prev, 0o644)
			_ = os.Remove(dst + ".ocliv-bak")
			return fmt.Errorf("validation failed, previous config restored: %w", err)
		}
		_ = os.Remove(dst)
		return fmt.Errorf("validation failed, installed candidate removed (no previous config): %w", err)
	}
	if !existed {
		if err := os.WriteFile(newFileSentinel(dst), nil, 0o644); err != nil {
			return fmt.Errorf("journaling new file %s: %w", dst, err)
		}
	}
	return nil
}

// RollbackInstalled undoes one managed file after a later
// provisioning step fails: a backed-up file is restored, a journaled
// newly created file is removed. It reports whether it changed
// anything so the caller can reload the service manager when the
// on-disk configuration moved under it. Failures are reported —
// never silently ignored — and a backup whose restore failed is
// kept in place as a recovery artifact instead of being deleted.
func RollbackInstalled(dst string) (restored bool, err error) {
	if prev, err := os.ReadFile(dst + ".ocliv-bak"); err == nil {
		if werr := os.WriteFile(dst, prev, 0o644); werr != nil {
			return false, fmt.Errorf("rollback of %s failed, backup kept at %s.ocliv-bak: %w", dst, dst, werr)
		}
		if rerr := os.Remove(dst + ".ocliv-bak"); rerr != nil {
			return true, fmt.Errorf("rollback of %s restored but backup removal failed: %w", dst, rerr)
		}
		_ = os.Remove(newFileSentinel(dst))
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("rollback of %s cannot read backup: %w", dst, err)
	}
	if _, serr := os.Stat(newFileSentinel(dst)); serr == nil {
		if rerr := os.Remove(dst); rerr != nil && !os.IsNotExist(rerr) {
			return false, fmt.Errorf("rollback of %s cannot remove newly created file: %w", dst, rerr)
		}
		if rerr := os.Remove(newFileSentinel(dst)); rerr != nil && !os.IsNotExist(rerr) {
			return true, fmt.Errorf("rollback of %s removed but journal cleanup failed: %w", dst, rerr)
		}
		return true, nil
	} else if !os.IsNotExist(serr) {
		return false, fmt.Errorf("rollback of %s cannot read journal: %w", dst, serr)
	}
	return false, nil
}

// ReloadServiceManager re-reads unit files after a rollback changed
// them on disk. The unit install reloads the manager at install
// time, so without this the daemon would keep running the
// rolled-back configuration in memory. The Caddyfile install only
// validates (never reloads Caddy), so file-level rollback is
// already complete for Caddy.
func ReloadServiceManager() error {
	return runDaemonReload()
}

// CleanInstallBackup drops a consumed backup and journal sentinel
// after the whole operation succeeds. Neither is left behind a good
// install.
func CleanInstallBackup(dst string) {
	_ = os.Remove(dst + ".ocliv-bak")
	_ = os.Remove(newFileSentinel(dst))
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
