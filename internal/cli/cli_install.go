// Publisher binary self-install from relay release manifest.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/control"
	"ocliv/internal/installer"
)

// cmdUpdate is the simplified client update command:
//
//	ocliv update [--check] [--yes] [--relay URL] [--dir DIR] [--profile NAME]
//
// It reads the persisted relay URL for the active profile and delegates to
// the verified signed release installer (`cmdInstall`).
func cmdUpdate(argv []string) int {
	var relayURL, dir, profileFlag string
	var checkOnly, yes bool

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Fprintln(os.Stderr, "usage: ocliv update [--check] [--yes] [--relay URL] [--dir DIR] [--profile NAME]")
			return apperr.ExitOK
		case a == "--check":
			checkOnly = true
		case a == "--yes" || a == "-y":
			yes = true
		case a == "--relay" || strings.HasPrefix(a, "--relay="):
			v, ok := mcpFlagValue(argv, &i, "relay")
			if !ok {
				return apperr.ExitCLIValidation
			}
			relayURL = v
		case a == "--dir" || strings.HasPrefix(a, "--dir="):
			v, ok := mcpFlagValue(argv, &i, "dir")
			if !ok {
				return apperr.ExitCLIValidation
			}
			dir = v
		case a == "--profile" || strings.HasPrefix(a, "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profileFlag = v
		default:
			fmt.Fprintf(os.Stderr, "update: unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	if profileFlag == "" {
		profileFlag = config.ActiveProfile()
	}
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(profileFlag)
	}
	if relayURL == "" {
		fmt.Fprintln(os.Stderr, "update: no relay URL configured; pass --relay URL or enroll first")
		return apperr.ExitCLIValidation
	}
	installArgs := []string{"--relay", relayURL}
	if dir != "" {
		installArgs = append(installArgs, "--dir", dir)
	}
	if checkOnly {
		installArgs = append(installArgs, "--dry-run", "--yes")
	} else if yes {
		installArgs = append(installArgs, "--yes")
	}
	return cmdInstall(installArgs)
}

func cmdInstall(argv []string) int {
	var relayURL, manifestURL, artifactURL, dir string
	yes, dryRun, allowUnsignedDev := false, false, false

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Fprintln(os.Stderr, "usage: ocliv install --relay URL [--dir DIR] [--yes] [--dry-run]")
			fmt.Fprintln(os.Stderr, "       ocliv install --manifest-url URL [--artifact-url URL] [--dir DIR] [--yes] [--dry-run]")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "  --relay URL                      fetch manifest from relay's well-known endpoint")
			fmt.Fprintln(os.Stderr, "  --manifest-url URL               fetch manifest from explicit URL")
			fmt.Fprintln(os.Stderr, "  --artifact-url URL               download artifact from explicit URL (skips auto-detection)")
			fmt.Fprintln(os.Stderr, "  --dir DIR                        install directory (default: directory of current binary)")
			fmt.Fprintln(os.Stderr, "  --yes                            skip confirmation prompt")
			fmt.Fprintln(os.Stderr, "  --dry-run                        download and verify digest but do not install")
			fmt.Fprintln(os.Stderr, "  --allow-unsigned-dev-release     skip manifest signature check (loopback manifest URLs only)")
			return apperr.ExitOK
		case a == "--relay" || strings.HasPrefix(a, "--relay="):
			v, ok := mcpFlagValue(argv, &i, "relay")
			if !ok {
				return apperr.ExitCLIValidation
			}
			relayURL = v
		case a == "--manifest-url" || strings.HasPrefix(a, "--manifest-url="):
			v, ok := mcpFlagValue(argv, &i, "manifest-url")
			if !ok {
				return apperr.ExitCLIValidation
			}
			manifestURL = v
		case a == "--artifact-url" || strings.HasPrefix(a, "--artifact-url="):
			v, ok := mcpFlagValue(argv, &i, "artifact-url")
			if !ok {
				return apperr.ExitCLIValidation
			}
			artifactURL = v
		case a == "--dir" || strings.HasPrefix(a, "--dir="):
			v, ok := mcpFlagValue(argv, &i, "dir")
			if !ok {
				return apperr.ExitCLIValidation
			}
			dir = v
		case a == "--yes":
			yes = true
		case a == "--dry-run":
			dryRun = true
		case a == "--allow-unsigned-dev-release":
			allowUnsignedDev = true
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}

	if relayURL == "" && manifestURL == "" {
		fmt.Fprintln(os.Stderr, "error: --relay or --manifest-url required")
		fmt.Fprintln(os.Stderr, "usage: ocliv install --relay URL [--dir DIR] [--yes]")
		return apperr.ExitCLIValidation
	}
	if relayURL != "" && manifestURL != "" {
		fmt.Fprintln(os.Stderr, "error: --relay and --manifest-url are mutually exclusive")
		return apperr.ExitCLIValidation
	}

	if relayURL != "" {
		if err := control.ValidateRelayURL(relayURL); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitCLIValidation
		}
		manifestURL = installer.ManifestURL(relayURL)
	} else {
		if err := control.ValidateDownloadURL(manifestURL); err != nil {
			fmt.Fprintln(os.Stderr, "error: invalid --manifest-url: "+err.Error())
			return apperr.ExitCLIValidation
		}
	}
	if artifactURL != "" {
		if err := control.ValidateDownloadURL(artifactURL); err != nil {
			fmt.Fprintln(os.Stderr, "error: invalid --artifact-url: "+err.Error())
			return apperr.ExitCLIValidation
		}
	}

	artifactName := installer.ArtifactName(runtime.GOOS, runtime.GOARCH)

	client, err := control.HTTPClient(30 * time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: building HTTP client: "+err.Error())
		return apperr.ExitRelayTLS
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fmt.Fprintf(os.Stderr, "fetching manifest from %s...\n", manifestURL)
	var m *installer.ReleaseManifest
	if allowUnsignedDev {
		if !isLoopbackURL(manifestURL) {
			fmt.Fprintln(os.Stderr, "error: --allow-unsigned-dev-release is only permitted for loopback manifest URLs (127.x, localhost, ::1)")
			return apperr.ExitCLIValidation
		}
		fmt.Fprintln(os.Stderr, "warning: manifest signature check bypassed via --allow-unsigned-dev-release")
		m, err = installer.FetchManifest(ctx, client, manifestURL)
	} else {
		m, err = installer.FetchManifestSignedAny(ctx, client, manifestURL, installer.ProductionPublicKeys())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		if strings.Contains(err.Error(), "manifest signature") || strings.Contains(err.Error(), "unsigned manifest") {
			fmt.Fprintln(os.Stderr, "hint: use --allow-unsigned-dev-release for local development relays that don't publish a .sig file")
		}
		return apperr.ExitRelayTLS
	}
	fmt.Printf("manifest: commit=%s build_time=%s govulncheck=%s\n", m.Commit, m.BuildTime, m.Govulncheck)

	entry, ok := m.Artifacts[artifactName]
	if !ok {
		var available []string
		for k := range m.Artifacts {
			available = append(available, k)
		}
		fmt.Fprintf(os.Stderr, "error: no artifact for %s in manifest\navailable: %s\n", artifactName, strings.Join(available, ", "))
		return apperr.ExitCLIValidation
	}

	if artifactURL == "" {
		if relayURL != "" {
			artifactURL = installer.ArtifactURL(relayURL, artifactName)
		} else {
			fmt.Fprintln(os.Stderr, "error: --artifact-url required when using --manifest-url")
			return apperr.ExitCLIValidation
		}
	}

	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot determine executable path: "+err.Error())
			return apperr.ExitCLIValidation
		}
		dir = filepath.Dir(exe)
	}
	dst := filepath.Join(dir, "ocliv")

	if dryRun {
		fmt.Fprintf(os.Stderr, "dry-run: downloading %s...\n", artifactURL)
		tmpPath, err := installer.DownloadToTemp(ctx, client, artifactURL, entry.SHA256, dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitRelayTLS
		}
		defer os.Remove(tmpPath)
		if err := installer.ValidateBinaryCandidate(ctx, tmpPath, m); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitRelayTLS
		}
		fmt.Printf("verified: sha256=%s commit=%s — not installed (dry-run)\n", entry.SHA256, m.Commit)
		return apperr.ExitOK
	}

	if !yes {
		fmt.Printf("Install %s to %s? [y/N] ", artifactName, dst)
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || strings.ToLower(strings.TrimSpace(scanner.Text())) != "y" {
			fmt.Fprintln(os.Stderr, "aborted")
			return apperr.ExitCLIValidation
		}
	}

	fmt.Fprintf(os.Stderr, "downloading %s...\n", artifactURL)
	if err := installer.DownloadValidateAndInstall(ctx, client, artifactURL, entry.SHA256, dst, m); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitRelayTLS
	}
	fmt.Printf("installed: %s (commit %s)\n", dst, m.Commit)
	return apperr.ExitOK
}

// isLoopbackURL returns true if rawURL resolves to a loopback address.
func isLoopbackURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		strings.HasPrefix(host, "127.")
}
