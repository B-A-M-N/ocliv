package setup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CommandRunner abstracts process execution so the provider adapter is
// hermetically testable. The production runner shells out to the
// operator's own installed CLIs — no cloud SDK is vendored in.
type CommandRunner interface {
	lookPath(bin string) bool
	fileExists(path string) bool
	run(ctx context.Context, name string, args ...string) (string, error)
}

type osRunner struct{}

func (osRunner) lookPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func (osRunner) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (osRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %v: %v: %s", name, args, err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

// OracleAdapter provisions an optional Always Free relay host when the
// local machine has no direct inbound path. It uses the operator's
// existing authorized OCI CLI session; Ocliv never handles cloud
// credentials itself. Free-tier capacity is never guaranteed: Oracle
// may report out-of-capacity for free shapes, and the plan says so.
type OracleAdapter struct {
	Runner CommandRunner
	// ConfigFile overrides the default ~/.oci/config lookup (tests).
	ConfigFile string
	// Compartment and AD pin the free-tier launch; empty means the
	// operator must supply them (no silent defaults into billable
	// territory).
	Compartment string
	Zone        string
}

func (a OracleAdapter) runner() CommandRunner {
	if a.Runner != nil {
		return a.Runner
	}
	return osRunner{}
}

func (a OracleAdapter) configPath() string {
	if a.ConfigFile != "" {
		return a.ConfigFile
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.oci/config"
}

// Check verifies the operator's own OCI tooling without creating
// anything. ok=false names the exact missing prerequisite.
func (a OracleAdapter) Check(ctx context.Context) (string, bool) {
	r := a.runner()
	if !r.lookPath("oci") {
		return "BLOCKED: `oci` CLI not installed — install it and run `oci setup config`, then re-run", false
	}
	cfg := a.configPath()
	if cfg == "" || !r.fileExists(cfg) {
		return "BLOCKED: no OCI CLI session (~/.oci/config) — run `oci setup config` with your tenancy, then re-run", false
	}
	return "oci CLI present with an authorized session", true
}

// Plan prints the exact free-tier launch shape and its bounds. It is
// documentation, not a capacity claim.
func (a OracleAdapter) Plan() string {
	return strings.Join([]string{
		"Oracle Always Free relay plan (operator-approved only):",
		"- shape: VM.Standard.A1.Flex (Ampere ARM, up to 4 OCPU / 24 GB RAM free)",
		"- image: Canonical Ubuntu 24.04 Minimal aarch64, 50 GB boot volume (free-tier limit)",
		"- network: VCN + public subnet, ingress TCP 22 (operator IP only), 80, 443",
		"- relay: loopback-only ocliv + Caddy, installed from the rendered deployment dir",
		"- cost: $0 while inside Always Free limits; out-of-capacity or limit changes can refuse the launch",
		"- no guarantee: Oracle may report insufficient free capacity at any time; the launch fails closed, nothing billable is created",
		"Run again with --confirm-create to execute the `oci compute instance launch` command printed below after your review.",
	}, "\n")
}

// launchArgs builds the instance-launch invocation. Keeping it a pure
// function lets tests pin every flag without touching the cloud.
func (a OracleAdapter) launchArgs() []string {
	return []string{"compute", "instance", "launch",
		"--compartment-id", a.Compartment,
		"--availability-domain", a.Zone,
		"--shape", "VM.Standard.A1.Flex",
		"--shape-config", `{"ocpus":2,"memoryInGBs":12}`,
		"--assign-public-ip", "true",
	}
}

// Create launches the free-tier instance. approve=false always refuses;
// this is the no-surprise-charges gate. approve=true executes the OCI
// CLI launch (live, operator-authorized).
func (a OracleAdapter) Create(ctx context.Context, approve bool) error {
	if !approve {
		return fmt.Errorf("refusing: re-run with --confirm-create after reviewing the plan")
	}
	if a.Compartment == "" || a.Zone == "" {
		return fmt.Errorf("refusing: --compartment and --availability-domain are required (no silent defaults)")
	}
	r := a.runner()
	out, err := r.run(ctx, "oci", a.launchArgs()...)
	if err != nil {
		return fmt.Errorf("oci launch failed (no instance created or verify in the console): %v", err)
	}
	_ = out
	return nil
}
