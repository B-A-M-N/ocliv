package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

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
	// Enrollment stays manual until the auto-enrollment loop lands:
	// minting a code and completing login in one motion needs the
	// running relay's data dir and key handling that the next slice
	// wires up. Marking it auto now would overclaim.
	steps[len(steps)-1].Auto = false
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

// InstallCaddyfile backs up any existing edge config, installs the
// rendered one, and validates it. A failed validation restores the
// backup so a bad render can never leave Caddy unstartable.
func InstallCaddyfile(deployDir string) error {
	src := filepath.Join(deployDir, "Caddyfile")
	dst := "/etc/caddy/Caddyfile"
	bak := dst + ".ocliv-bak"
	if _, err := os.Stat(dst); err == nil {
		raw, err := os.ReadFile(dst)
		if err != nil {
			return err
		}
		if err := os.WriteFile(bak, raw, 0o644); err != nil {
			return err
		}
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		return err
	}
	if err := runCmd("caddy", "validate", "--config", dst, "--adapter", "caddyfile"); err != nil {
		if _, statErr := os.Stat(bak); statErr == nil {
			_ = runCmd("cp", bak, dst)
		}
		return err
	}
	return nil
}

// InstallUnit places the rendered systemd unit and reloads the
// manager. It starts nothing.
func InstallUnit(deployDir string) error {
	src := filepath.Join(deployDir, "ocliv-relay.service")
	dst := "/etc/systemd/system/ocliv-relay.service"
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		return err
	}
	return runCmd("systemctl", "daemon-reload")
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
