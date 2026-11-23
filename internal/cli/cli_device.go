package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/control"
	"github.com/B-A-M-N/ocliv/internal/relay"
	"github.com/B-A-M-N/ocliv/internal/store"
)

// cmdDevice is the operator-facing device enrollment and management command:
//
//	ocliv device add USER@HOST [--tenant NAME] [--relay URL] [--data DIR] [--profile NAME] [--install]
//	ocliv device add --local-user USER [--tenant NAME] [--relay URL] [--data DIR] [--profile NAME]
//	ocliv device list [--data DIR]
//	ocliv device revoke KEY_ID [--data DIR]
func cmdDevice(argv []string) int {
	if len(argv) == 0 || argv[0] == "--help" || argv[0] == "-h" {
		printDeviceUsage()
		if len(argv) == 0 {
			return apperr.ExitCLIValidation
		}
		return apperr.ExitOK
	}
	switch argv[0] {
	case "add":
		return cmdDeviceAdd(argv[1:])
	case "list", "ls":
		return cmdRelayKeys(argv[1:])
	case "revoke":
		return cmdRelayRevokeKey(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "device: unknown subcommand %q\n", argv[0])
		printDeviceUsage()
		return apperr.ExitCLIValidation
	}
}

func printDeviceUsage() {
	fmt.Fprintln(os.Stderr, "usage: ocliv device add USER@HOST [--tenant default] [--relay URL] [--data DIR] [--profile NAME] [--install]")
	fmt.Fprintln(os.Stderr, "       ocliv device add --local-user USER [--tenant default] [--relay URL] [--data DIR] [--profile NAME]")
	fmt.Fprintln(os.Stderr, "       ocliv device list [--data DIR]")
	fmt.Fprintln(os.Stderr, "       ocliv device revoke KEY_ID [--data DIR]")
}

func detectLocalRelayURL() string {
	if v := strings.TrimSpace(os.Getenv("OCLIV_RELAY_URL")); v != "" {
		return v
	}
	if f, err := os.Open("/etc/ocliv/relay.env"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		var domain, mcpHost string
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch strings.TrimSpace(k) {
			case "OCLIV_RELAY_URL":
				if v != "" {
					return v
				}
			case "OCLIV_MCP_HOST":
				mcpHost = v
			case "OCLIV_DOMAIN":
				domain = v
			}
		}
		if mcpHost != "" {
			return "https://" + mcpHost
		}
		if domain != "" {
			return "https://" + domain
		}
	}
	return ""
}

func validLocalUsername(u string) bool {
	if u == "" || len(u) > 64 || strings.HasPrefix(u, "-") {
		return false
	}
	for _, r := range u {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// validProfileName constrains profile names to safe literal characters
// matching ^[A-Za-z0-9._-]+$ (no leading '-').
func validProfileName(p string) bool {
	if p == "" || len(p) > 64 || strings.HasPrefix(p, "-") {
		return false
	}
	for _, r := range p {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// shellQuote wraps s in POSIX single quotes, escaping embedded single quotes
// via '\” so every byte is treated literally by the remote POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// buildSSHCommandString joins argv into a single POSIX-shell-safe command
// string so OpenSSH remote shell execution preserves exact argv boundaries.
func buildSSHCommandString(args ...string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	return strings.Join(quoted, " ")
}

// buildSSHLoginCommand builds the remote command string for `ocliv login`
// reading the one-time enrollment code from stdin.
func buildSSHLoginCommand(relayURL, profile string) string {
	args := []string{"ocliv", "login", "--relay", relayURL, "--code-file", "-"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	return buildSSHCommandString(args...)
}

// buildSSHInstallCommand builds a POSIX-shell-safe remote command string that
// downloads the signed client bootstrap script to a temporary file, verifies
// download success before execution, runs it with quoted arguments, and cleans
// up the temporary file on exit.
func buildSSHInstallCommand(relayURL string) string {
	installURL := strings.TrimRight(relayURL, "/") + "/install-client.sh"
	return fmt.Sprintf(
		`tmp=$(mktemp) && trap 'rm -f "$tmp"' EXIT && curl -fsSL %s -o "$tmp" && sh "$tmp" --relay %s --yes`,
		shellQuote(installURL),
		shellQuote(relayURL),
	)
}

func cmdDeviceAdd(argv []string) int {
	_, dataDir, _ := relayFlags(argv)
	var target, localUser, relayURL, tenant, profile string
	var autoInstall bool

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--help" || a == "-h":
			printDeviceUsage()
			return apperr.ExitOK
		case a == "--local-user" || strings.HasPrefix(a, "--local-user="):
			v, ok := mcpFlagValue(argv, &i, "local-user")
			if !ok {
				return apperr.ExitCLIValidation
			}
			localUser = v
		case a == "--target" || strings.HasPrefix(a, "--target="):
			v, ok := mcpFlagValue(argv, &i, "target")
			if !ok {
				return apperr.ExitCLIValidation
			}
			target = v
		case a == "--relay" || strings.HasPrefix(a, "--relay="):
			v, ok := mcpFlagValue(argv, &i, "relay")
			if !ok {
				return apperr.ExitCLIValidation
			}
			relayURL = v
		case a == "--tenant" || strings.HasPrefix(a, "--tenant="):
			v, ok := mcpFlagValue(argv, &i, "tenant")
			if !ok {
				return apperr.ExitCLIValidation
			}
			tenant = v
		case a == "--profile" || strings.HasPrefix(a, "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		case a == "--data" || strings.HasPrefix(a, "--data="):
			_, _ = mcpFlagValue(argv, &i, "data")
		case a == "--install":
			autoInstall = true
		case !strings.HasPrefix(a, "-") && target == "":
			target = a
		default:
			fmt.Fprintf(os.Stderr, "device add: unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}

	if target == "" && localUser == "" {
		printDeviceUsage()
		return apperr.ExitCLIValidation
	}
	if target != "" && localUser != "" {
		fmt.Fprintln(os.Stderr, "device add: specify either USER@HOST or --local-user USER, not both")
		return apperr.ExitCLIValidation
	}
	if relayURL == "" {
		relayURL = detectLocalRelayURL()
	}
	if relayURL == "" {
		fmt.Fprintln(os.Stderr, "device add: --relay URL required (could not auto-detect from /etc/ocliv/relay.env)")
		return apperr.ExitCLIValidation
	}
	if err := control.ValidateRelayURL(relayURL); err != nil {
		fmt.Fprintf(os.Stderr, "device add: invalid --relay URL: %v\n", err)
		return apperr.ExitCLIValidation
	}
	if profile != "" && !validProfileName(profile) {
		fmt.Fprintln(os.Stderr, "device add: invalid --profile (must match ^[A-Za-z0-9._-]+$ without leading '-')")
		return apperr.ExitCLIValidation
	}
	if tenant == "" {
		tenant = "default"
	}

	if localUser != "" {
		return enrollLocalUserDevice(dataDir, relayURL, tenant, localUser, profile)
	}
	return enrollSSHDevice(dataDir, relayURL, tenant, target, profile, autoInstall)
}

// enrollLocalUserDevice enrolls a same-host user by minting a one-time
// enrollment code and running `ocliv login --code-file -` as the target
// unprivileged user via stdin. Root never writes identity/config files into
// another user's home directory.
func enrollLocalUserDevice(dataDir, relayURL, tenant, localUser, profile string) int {
	if !validLocalUsername(localUser) {
		fmt.Fprintf(os.Stderr, "device add: invalid --local-user %q\n", localUser)
		return apperr.ExitCLIValidation
	}
	selfBin, err := os.Executable()
	if err != nil || selfBin == "" {
		selfBin = "ocliv"
	}
	restrictFileCreation()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()

	code, err := relay.IssueEnrollmentCode(db, tenant, 15*time.Minute, "operator")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}

	loginArgs := []string{"login", "--relay", relayURL, "--code-file", "-"}
	if profile != "" {
		loginArgs = append(loginArgs, "--profile", profile)
	}

	var cmd *exec.Cmd
	if sudoPath, serr := exec.LookPath("sudo"); serr == nil {
		args := append([]string{"-u", localUser, "-H", "--", selfBin}, loginArgs...)
		cmd = exec.Command(sudoPath, args...)
	} else {
		fmt.Fprintln(os.Stderr, "device add: `sudo` is required for --local-user privilege drop")
		return apperr.ExitInternal
	}
	cmd.Stdin = strings.NewReader(code + "\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "device add: local-user login failed for %s: %v\n", localUser, err)
		return apperr.ExitInternal
	}
	fmt.Printf("✓ %s enrolled (local)\n  tenant: %s\n  relay:  %s\n", localUser, tenant, relayURL)
	return apperr.ExitOK
}

// enrollSSHDevice orchestrates secure auto-pairing over an authenticated SSH
// channel: connectivity check -> client presence check (optional verified
// install with --install) -> IssueEnrollmentCode() -> pipe code via SSH stdin
// to `ocliv login --code-file -`.
func enrollSSHDevice(dataDir, relayURL, tenant, target, profile string, autoInstall bool) int {
	if strings.HasPrefix(target, "-") || strings.ContainsAny(target, " \t\r\n") {
		fmt.Fprintln(os.Stderr, "device add: target must be USER@HOST without leading '-' or whitespace")
		return apperr.ExitCLIValidation
	}

	// 1. Check SSH connectivity and whether `ocliv` is installed on the target.
	checkCmd := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", target, "command -v ocliv >/dev/null 2>&1")
	if err := checkCmd.Run(); err != nil {
		// Distinguish SSH connectivity failure vs missing ocliv binary.
		pingCmd := exec.Command("ssh", "-o", "ConnectTimeout=10", "--", target, "true")
		pingCmd.Stdin = os.Stdin
		pingCmd.Stdout = os.Stdout
		pingCmd.Stderr = os.Stderr
		if pingErr := pingCmd.Run(); pingErr != nil {
			fmt.Fprintf(os.Stderr, "device add: SSH connection to %s failed: %v\n", target, pingErr)
			fmt.Fprintf(os.Stderr, "If SSH is unavailable, run `ocliv pair %s` on that machine instead.\n", relayURL)
			return apperr.ExitInternal
		}
		// SSH works, check again interactively in case SSH needed a passphrase/agent.
		binCheck := exec.Command("ssh", "--", target, "command -v ocliv >/dev/null 2>&1")
		if binErr := binCheck.Run(); binErr != nil {
			if !autoInstall {
				fmt.Fprintf(os.Stderr, "device add: `ocliv` is not installed on %s.\n", target)
				fmt.Fprintf(os.Stderr, "Install it on %s first, or re-run with `--install` to download the signed client release from %s.\n", target, relayURL)
				return apperr.ExitCLIValidation
			}
			installCmd := exec.Command("ssh", "--", target, buildSSHInstallCommand(relayURL))
			installCmd.Stdin = os.Stdin
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if ierr := installCmd.Run(); ierr != nil {
				fmt.Fprintf(os.Stderr, "device add: remote client install failed on %s: %v\n", target, ierr)
				return apperr.ExitInternal
			}
		}
	}

	// 2. Mint a 15-minute enrollment capability and pipe it over SSH stdin.
	restrictFileCreation()
	db, err := store.Open(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()

	code, err := relay.IssueEnrollmentCode(db, tenant, 15*time.Minute, "operator")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return exitForRelayErr(err)
	}

	cmd := exec.Command("ssh", "--", target, buildSSHLoginCommand(relayURL, profile))
	cmd.Stdin = strings.NewReader(code + "\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "device add: remote login failed on %s: %v\n", target, err)
		return apperr.ExitInternal
	}

	hostLabel := target
	if _, h, ok := strings.Cut(target, "@"); ok && h != "" {
		hostLabel = h
	}
	fmt.Printf("✓ %s enrolled\n  tenant: %s\n  relay:  %s\n", hostLabel, tenant, relayURL)
	return apperr.ExitOK
}
