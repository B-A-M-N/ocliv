package setup

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"ocliv/packaging/systemd"
)

// DefaultCleanHostArtifacts names the destinations a complete clean-host
// bootstrap owns on the standard systemd/Caddy host. Every managed
// destination rolls back on a later step's failure (managed files via
// *.ocliv-bak/sentinel; the binary via *.ocliv-bak; the data dir via
// *.ocliv-new, only when this run created it).
var DefaultCleanHostArtifacts = struct {
	Binary    string
	Launcher  string
	DataDir   string
	EnvFile   string
	Caddyfile string
	Unit      string
}{
	Binary:    "/usr/local/bin/ocliv",
	Launcher:  "/usr/local/bin/ocliv-relay-launch.sh",
	DataDir:   "/var/lib/ocliv",
	EnvFile:   "/etc/ocliv/relay.env",
	Caddyfile: "/etc/caddy/Caddyfile",
	Unit:      "/etc/systemd/system/ocliv-relay.service",
}

// RelayUser is the system account the relay unit runs as; a clean host
// does not have it until bootstrap creates it.
const RelayUser = "ocliv"

// ManagedMarker tags files ocliv setup owns. An existing destination
// without the marker is treated as unrelated (possibly another
// application's config) and is never overwritten automatically.
const ManagedMarker = "# managed by ocliv setup"

// runCaddyValidate and runDaemonReload are indirection points so
// install/rollback behavior is testable without a live Caddy or
// systemd.
// validateStagedBinary is a TEST HOOK for InstallBinaryTo's publish
// boundary: the staged candidate is validated immediately before the
// atomic rename into place, and failure here models an interruption
// before replacement (dst is untouched and the staged candidate is
// swept). The default is a no-op because the candidate's integrity is
// established by staging an exact byte copy and publishing it with an
// atomic rename + fsync; there is no separate signature to check at
// install time. Tests inject a failure to prove an invalid candidate is
// never published. It is exported-package-internal, not a public API.
var validateStagedBinary = func(string) error { return nil }

var runCaddyValidate = func(dst string) error {
	return runCmd("caddy", "validate", "--config", dst, "--adapter", "caddyfile")
}
var runDaemonReload = func() error {
	return runCmd("systemctl", "daemon-reload")
}

// ServiceState records whether a systemd unit was enabled and/or active
// before setup changed it. Rollback reverses only transitions this run
// actually performed and never stops a service that was already running.
type ServiceState struct {
	Enabled bool
	Active  bool
}

var captureServiceState = func(unit string) ServiceState {
	st := ServiceState{}
	if err := runCmd("systemctl", "is-enabled", unit); err == nil {
		st.Enabled = true
	}
	if err := runCmd("systemctl", "is-active", unit); err == nil {
		st.Active = true
	}
	return st
}

var restoreServiceState = func(unit string, before ServiceState) error {
	if !before.Enabled {
		if err := runCmd("systemctl", "disable", unit); err != nil {
			return err
		}
	}
	if !before.Active {
		if err := runCmd("systemctl", "stop", unit); err != nil {
			return err
		}
	}
	return nil
}

// startedUnits tracks which units this setup run actually transitioned
// (enable/start). Only those are reversed on rollback; a service that was
// already running stays running.
var (
	startedUnits = map[string]bool{}
	preState     = map[string]ServiceState{}
)

// CaptureServiceState records the current enablement/activity of a unit.
func CaptureServiceState(unit string) ServiceState { return captureServiceState(unit) }

// RestoreService reverses the transitions this run performed on a unit.
func RestoreService(unit string) error {
	before, ok := preState[unit]
	if !ok {
		before = ServiceState{}
	}
	return restoreServiceState(unit, before)
}

// ResetStartedUnits clears the per-run transition tracker.
func ResetStartedUnits() {
	startedUnits = map[string]bool{}
	preState = map[string]ServiceState{}
}

// MarkPreState seeds the tracker with the units' pre-setup state.
func MarkPreState(m map[string]ServiceState) {
	for k, v := range m {
		preState[k] = v
	}
}

// MarkStarted records that this run transitioned a unit (enable/start).
func MarkStarted(unit string) { startedUnits[unit] = true }

// StartedUnits reports which units this run transitioned (for tests).
func StartedUnits() map[string]bool {
	out := map[string]bool{}
	for k, v := range startedUnits {
		out[k] = v
	}
	return out
}

// runCaddyActivate enables and starts Caddy, then reloads the newly
// installed Caddyfile. A clean host usually has Caddy installed but
// not running; an upgraded host has it running with the old config.
// Indirection keeps it testable without a live systemd/Caddy.
var runCaddyActivate = func() error {
	if err := runCmd("systemctl", "enable", "--now", "caddy"); err != nil {
		return err
	}
	return runCmd("systemctl", "reload", "caddy")
}

// serviceUserExists / serviceUserAdd wrap the account tools. A system
// account is NEVER removed by any rollback here: deleting an account
// that other artifacts may reference is a destructive act outside this
// operation's blast radius, and an unused account is harmless.
var serviceUserExists = func(name string) bool {
	return runCmd("id", name) == nil
}

var serviceUserAdd = func(name, home string) error {
	return runCmd("useradd", "--system", "--home-dir", home, "--no-create-home", "--shell", "/usr/sbin/nologin", name)
}

// lookupRelayUser and chownPath are indirection points for the data
// directory step: tests resolve a fake account instead of a real one,
// and never chown anything.
var lookupRelayUser = func(name string) (uid, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

var chownPath = os.Chown

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
	DataDir      string
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
	caddyDst := DefaultCleanHostArtifacts.Caddyfile
	unitDst := DefaultCleanHostArtifacts.Unit
	binDst := DefaultCleanHostArtifacts.Binary
	launcherDst := DefaultCleanHostArtifacts.Launcher
	envDst := DefaultCleanHostArtifacts.EnvFile
	dataDir := env.DataDir
	if dataDir == "" {
		dataDir = DefaultCleanHostArtifacts.DataDir
	}
	mk := func(title, manual string) Step {
		return Step{Title: title, Auto: env.AsRoot, Manual: manual}
	}
	steps = []Step{
		// Order is prerequisite order: the account and data dir
		// must exist before the relay can start; the Caddyfile must
		// exist before Caddy can load it; the unit must exist
		// before it is enabled.
		mk("create service account",
			fmt.Sprintf("id %s || useradd --system --home-dir %s --no-create-home --shell /usr/sbin/nologin %s",
				RelayUser, dataDir, RelayUser)),
		mk("install binary",
			fmt.Sprintf("install -o root -g root -m 0755 $(command -v ocliv) %s", binDst)),
		mk("install launcher",
			fmt.Sprintf("install -o root -g root -m 0755 packaging/systemd/ocliv-relay-launch.sh %s", launcherDst)),
		mk("create data directory",
			fmt.Sprintf("install -d -o %s -g %s -m 0700 %s%s",
				RelayUser, RelayUser, dataDir, dataDirCaution(dataDir))),
		mk("install relay environment",
			fmt.Sprintf("cp %s %s && chmod 0600 %s",
				filepath.Join(env.DeployDir, "relay.env"), envDst, envDst)),
		mk("install Caddyfile",
			fmt.Sprintf("cp %s %s && caddy validate --config %s --adapter caddyfile",
				filepath.Join(env.DeployDir, "Caddyfile"), caddyDst, caddyDst)),
		mk("activate and reload Caddy",
			"systemctl enable --now caddy && systemctl reload caddy"),
		mk("install systemd unit",
			fmt.Sprintf("cp %s %s && systemctl daemon-reload",
				filepath.Join(env.DeployDir, "ocliv-relay.service"), unitDst)),
		mk("enable and start relay",
			"systemctl enable --now ocliv-relay && systemctl is-active ocliv-relay"),
		mk("enroll this machine",
			fmt.Sprintf("ocliv relay issue-enroll --data %s --tenant home && ocliv login --relay https://%s --code-file -", dataDir, env.Hostname)),
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
// The file mode is part of the contract (0644 here); callers whose
// artifact is more restrictive (the env file) use installManagedFileMode.
// The backup keeps the PREVIOUS mode so a restore also restores the
// previous permissions, never silently widening them.
func installManagedFile(dst string, candidate []byte, validate func(string) error) error {
	return installManagedFileMode(dst, candidate, 0o644, validate)
}

func installManagedFileMode(dst string, candidate []byte, perm os.FileMode, validate func(string) error) error {
	existed := true
	var prevMode os.FileMode = 0o644
	if prev, err := os.ReadFile(dst); err == nil {
		if !strings.Contains(string(prev), ManagedMarker) {
			return fmt.Errorf("refusing to overwrite unmanaged %s (no %q marker): back it up, move it aside, or adopt it by adding the marker line, then re-run", dst, ManagedMarker)
		}
		if fi, serr := os.Stat(dst); serr == nil {
			prevMode = fi.Mode().Perm()
		}
		if err := os.WriteFile(dst+".ocliv-bak", prev, prevMode); err != nil {
			return fmt.Errorf("backing up %s: %w", dst, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", dst, err)
	} else {
		existed = false
	}
	if err := os.WriteFile(dst, candidate, perm); err != nil {
		return fmt.Errorf("installing %s: %w", dst, err)
	}
	if err := os.Chmod(dst, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", dst, err)
	}
	if validate != nil {
		if err := validate(dst); err != nil {
			if prev, rerr := os.ReadFile(dst + ".ocliv-bak"); rerr == nil {
				// The restore write is itself fallible (disk full,
				// permissions, hostile post-write state). A failed
				// restore must be loud, and the backup must survive
				// as a recovery artifact — never silently deleted.
				if werr := os.WriteFile(dst, prev, prevMode); werr != nil {
					return fmt.Errorf("validation failed and previous config restore failed, backup kept at %s.ocliv-bak: %v: %w", dst, werr, err)
				}
				if rerr := os.Remove(dst + ".ocliv-bak"); rerr != nil {
					return fmt.Errorf("validation failed, previous config restored but backup removal failed: %v: %w", rerr, err)
				}
				return fmt.Errorf("validation failed, previous config restored: %w", err)
			}
			if rerr := os.Remove(dst); rerr != nil && !os.IsNotExist(rerr) {
				return fmt.Errorf("validation failed and installed candidate removal failed: %v: %w", rerr, err)
			}
			return fmt.Errorf("validation failed, installed candidate removed (no previous config): %w", err)
		}
	}
	if !existed {
		if err := os.WriteFile(newFileSentinel(dst), nil, 0o644); err != nil {
			return fmt.Errorf("journaling new file %s: %w", dst, err)
		}
	}
	return nil
}

// InstallEnvTo installs the rendered relay environment at dst: the
// directory is 0700, the file is 0600 (root-owned), and the managed
// marker is prepended so a re-run cannot clobber an unrelated
// environment file and a failure can roll it back. This is the file
// the unit's EnvironmentFile reads — it is how the service learns its
// domain and public hostnames, and with no validation needed it is
// checked structurally here: a missing OCLIV_DOMAIN is refused,
// because a relay started without one would fail at startup anyway.
func InstallEnvTo(deployDir, dst string) error {
	raw, err := os.ReadFile(filepath.Join(deployDir, "relay.env"))
	if err != nil {
		return fmt.Errorf("rendered relay.env unreadable: %w", err)
	}
	if !strings.Contains(string(raw), "OCLIV_DOMAIN=") {
		return fmt.Errorf("rendered relay.env carries no OCLIV_DOMAIN=; refusing to install an environment the relay cannot start with")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(dst), err)
	}
	content := append([]byte(ManagedMarker+" (relay environment)\n"), raw...)
	return installManagedFileMode(dst, content, 0o600, nil)
}

// InstallLauncherTo installs the ExecStart wrapper the relay unit
// runs: 0755, marker on the line after the shebang (the marker must
// never displace #!, or the kernel cannot exec the script), rolled
// back like any other managed file. The content comes from the
// embedded packaging source, so a clean host gets exactly the script
// the reviewed unit expects with no checkout.
func InstallLauncherTo(dst string) error {
	raw := systemd.RelayLauncher()
	content := raw
	if strings.HasPrefix(raw, "#!") {
		nl := strings.IndexByte(raw, '\n')
		if nl < 0 {
			return fmt.Errorf("embedded launcher has no interpreter line")
		}
		content = raw[:nl+1] + ManagedMarker + " (launcher)\n" + raw[nl+1:]
	}
	return installManagedFileMode(dst, []byte(content), 0o755, nil)
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
		// Restore the previous PERMISSIONS with the previous
		// content: a rollback must put the host back the way it
		// was, never silently widen or narrow a managed file.
		mode := os.FileMode(0o644)
		if fi, serr := os.Stat(dst + ".ocliv-bak"); serr == nil {
			mode = fi.Mode().Perm()
		}
		if werr := os.WriteFile(dst, prev, mode); werr != nil {
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

// ActivateAndReloadCaddy brings the edge up on this host: enables and
// starts Caddy (a clean host has it installed but not running), then
// reloads so a just-upgraded host picks up the new Caddyfile.
func ActivateAndReloadCaddy() error {
	return runCaddyActivate()
}

// ReloadCaddy re-reads the on-disk edge config after a rollback moved
// it under a running Caddy. A STOPPED Caddy is never started here:
// enablement/startup belongs to the activate step, and rollback must
// not resurrect state the operator had deliberately taken down.
var runCaddyReload = func() error {
	return runCmd("systemctl", "reload", "caddy")
}

func ReloadCaddy() error { return runCaddyReload() }

// dataDirCaution warns the operator when the chosen data dir diverges
// from the one the relay unit pins (WorkingDirectory +
// ReadWritePaths=/var/lib/ocliv): the unit would block the relay from
// writing anywhere else, so the unit's paths must match.
func dataDirCaution(dataDir string) string {
	if dataDir == DefaultCleanHostArtifacts.DataDir {
		return ""
	}
	return fmt.Sprintf(" (note: the relay unit pins WorkingDirectory and ReadWritePaths to %s; adjust the unit to %s or the relay cannot write its database there)",
		DefaultCleanHostArtifacts.DataDir, dataDir)
}

// EnsureServiceAccount creates the relay service account when missing
// and leaves an existing one untouched. It NEVER removes an account:
// rollback of a failed bootstrap keeps the account, because removing
// a system account other artifacts may reference is a destructive act
// outside this operation's blast radius.
func EnsureServiceAccount(name, homeDir string) error {
	if serviceUserExists(name) {
		return nil
	}
	return serviceUserAdd(name, homeDir)
}

// EnsureDataDir creates dir when missing, fixes its owner to the
// service account and its mode to 0700 either way, and journals a
// newly created directory so RollbackDataDir can undo exactly this
// run's mkdir. An existing database directory is NEVER removed — it
// holds the relay's state.
func EnsureDataDir(dir, user string) error {
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", dir)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", dir, err)
	} else {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
		if err := os.WriteFile(newFileSentinel(dir), nil, 0o644); err != nil {
			return fmt.Errorf("journaling new directory %s: %w", dir, err)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	uid, gid, err := lookupRelayUser(user)
	if err != nil {
		return fmt.Errorf("resolving service account %q: %w", user, err)
	}
	if err := chownPath(dir, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %s: %w", dir, user, err)
	}
	return nil
}

// RollbackDataDir removes a directory this run created (and journaled);
// it refuses to touch a pre-existing one. It reports whether it
// changed anything so the caller can reload what depends on it.
func RollbackDataDir(dir string) (restored bool, err error) {
	if _, serr := os.Stat(newFileSentinel(dir)); serr == nil {
		// A newly created directory that has become nonempty (e.g. the
		// relay wrote its SQLite database before a later step failed)
		// contains generated authorization state. Never recursively
		// delete it: preserve it and report the exact path so the
		// operator can inspect and remove it deliberately.
		entries, derr := os.ReadDir(dir)
		if derr != nil {
			return false, fmt.Errorf("rollback of %s cannot inspect contents: %w", dir, derr)
		}
		if len(entries) > 1 || (len(entries) == 1 && entries[0].Name() != filepath.Base(newFileSentinel(dir))) {
			return false, fmt.Errorf(
				"rollback of %s refused: the newly created directory is not empty (it contains generated relay state); preserve it and remove it manually after inspection", dir)
		}
		if rerr := os.Remove(dir); rerr != nil && !os.IsNotExist(rerr) {
			return false, fmt.Errorf("rollback of %s cannot remove newly created directory: %w", dir, rerr)
		}
		if rerr := os.Remove(newFileSentinel(dir)); rerr != nil && !os.IsNotExist(rerr) {
			return true, fmt.Errorf("rollback of %s removed but journal cleanup failed: %w", dir, rerr)
		}
		return true, nil
	} else if !os.IsNotExist(serr) {
		return false, fmt.Errorf("rollback of %s cannot read journal: %w", dir, serr)
	}
	return false, nil
}

// InstallBinaryTo installs the staged relay binary at dst (0755,
// root-owned). The candidate is staged on the destination filesystem
// (<dst>.ocliv-staged), validated at the publish boundary, and
// atomically renamed into place, so an interruption can never leave a
// partially written binary at dst. A previous binary is preserved at
// <dst>.ocliv-bak and the FIRST candidate wins across consecutive
// runs: re-running the bootstrap must not overwrite the original
// rollback point with an already-installed binary. RollbackBinary
// restores or removes it.
func InstallBinaryTo(src, dst string) error {
	prev := dst + ".ocliv-bak"
	if raw, err := os.ReadFile(dst); err == nil {
		if _, berr := os.Stat(prev); os.IsNotExist(berr) {
			if err := os.WriteFile(prev, raw, 0o755); err != nil {
				return fmt.Errorf("backing up %s: %w", dst, err)
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", dst, err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("staged binary %s unreadable: %w", src, err)
	}
	// Stage the candidate on the DESTINATION filesystem (a rename
	// across filesystems is not atomic) under a UNIQUE name: a fixed
	// staged path would let two concurrent installs write the same
	// temporary and one rename could publish a torn mix. fsync the
	// staged file so its content is durable before the rename, then
	// rename atomically into place and fsync the directory so the
	// rename itself is journaled (power-loss durability). An
	// interrupted write can only ever touch the staged artifact, which
	// is swept on failure — dst is either the previous binary or the
	// complete new one, never a partial write.
	staged := fmt.Sprintf("%s.ocliv-staged-%d", dst, os.Getpid())
	sweep := func() { _ = os.Remove(staged) }
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return fmt.Errorf("staging %s: %w", staged, err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		sweep()
		return fmt.Errorf("staging %s: %w", staged, err)
	}
	if err := f.Chmod(0o755); err != nil {
		_ = f.Close()
		sweep()
		return fmt.Errorf("chmod %s: %w", staged, err)
	}
	// Durable content before the rename is published.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		sweep()
		return fmt.Errorf("syncing staged %s: %w", staged, err)
	}
	if err := f.Close(); err != nil {
		sweep()
		return fmt.Errorf("closing staged %s: %w", staged, err)
	}
	if err := validateStagedBinary(staged); err != nil {
		sweep()
		return fmt.Errorf("validating staged binary %s: %w", staged, err)
	}
	if err := os.Rename(staged, dst); err != nil {
		sweep()
		return fmt.Errorf("installing %s: %w", dst, err)
	}
	// Durable rename: flush the directory so the new name survives a
	// power loss (best-effort on filesystems without directory fsync).
	dir, err := os.Open(filepath.Dir(dst))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// RollbackBinary restores the preserved previous binary, or removes a
// newly installed one when there was no previous binary. It reports
// whether it changed anything; the same "first candidate wins" backup
// is then dropped, letting the next install capture a fresh point.
func RollbackBinary(dst string) (restored bool, err error) {
	prev := dst + ".ocliv-bak"
	if raw, rerr := os.ReadFile(prev); rerr == nil {
		// Atomic restore: stage the backup on the destination filesystem
		// and rename it into place (a direct os.WriteFile could leave a
		// torn binary at dst under an interrupted rollback). On any
		// failure the backup is kept and dst is untouched.
		staged := fmt.Sprintf("%s.ocliv-rollback-%d", dst, os.Getpid())
		werr := func() error {
			f, ferr := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
			if ferr != nil {
				return ferr
			}
			if _, ferr = f.Write(raw); ferr != nil {
				_ = f.Close()
				return ferr
			}
			if ferr = f.Chmod(0o755); ferr != nil {
				_ = f.Close()
				return ferr
			}
			if ferr = f.Sync(); ferr != nil {
				_ = f.Close()
				return ferr
			}
			return f.Close()
		}()
		if werr != nil {
			_ = os.Remove(staged)
			return false, fmt.Errorf("binary rollback of %s failed, backup kept at %s: %w", dst, prev, werr)
		}
		if rerr := os.Rename(staged, dst); rerr != nil {
			_ = os.Remove(staged)
			return false, fmt.Errorf("binary rollback of %s failed, backup kept at %s: %w", dst, prev, rerr)
		}
		if rerr := os.Remove(prev); rerr != nil && !os.IsNotExist(rerr) {
			return true, fmt.Errorf("binary rollback of %s restored but backup removal failed: %w", dst, rerr)
		}
		return true, nil
	} else if !os.IsNotExist(rerr) {
		return false, fmt.Errorf("binary rollback of %s cannot read backup: %w", dst, rerr)
	}
	if _, serr := os.Stat(dst); serr == nil {
		if rerr := os.Remove(dst); rerr != nil && !os.IsNotExist(rerr) {
			return false, fmt.Errorf("binary rollback of %s cannot remove newly installed binary: %w", dst, rerr)
		}
		return true, nil
	} else if !os.IsNotExist(serr) {
		return false, fmt.Errorf("binary rollback of %s cannot stat destination: %w", dst, serr)
	}
	return false, nil
}
