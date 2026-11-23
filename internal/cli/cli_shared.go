// Shared agent credentials and terminal helpers used across CLI commands.
package cli

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"

	"golang.org/x/term"
)

// agentFiles resolves key/config/lease paths. When invoked via sudo (euid == 0
// with SUDO_USER set and no explicit OCLIV_CONFIG_DIR override), it resolves the
// invoking user's ~/.config/ocliv so setup/enroll never strands credentials under /root.
func agentFiles() (dir, keyPath, cfgPath string, err error) {
	return agentFilesWithEuid(os.Geteuid())
}

func agentFilesWithEuid(euid int) (dir, keyPath, cfgPath string, err error) {
	if euid == 0 && os.Getenv("OCLIV_CONFIG_DIR") == "" {
		if su := strings.TrimSpace(os.Getenv("SUDO_USER")); su != "" && su != "root" {
			if u, lerr := user.Lookup(su); lerr == nil && u.HomeDir != "" {
				dir = filepath.Join(u.HomeDir, ".config", "ocliv")
				if prof := config.ActiveProfile(); prof != "" && prof != "default" {
					dir = filepath.Join(dir, "profiles", prof)
				}
				return dir, filepath.Join(dir, config.AgentKeyFile), filepath.Join(dir, config.ConfigFile), nil
			}
		}
	}
	dir, err = config.DataDir()
	if err != nil {
		return "", "", "", err
	}
	return dir, filepath.Join(dir, config.AgentKeyFile), filepath.Join(dir, config.ConfigFile), nil
}

// agentFilesForProfile resolves key/config/lease paths for an explicit
// profile so service operations never silently switch profiles.
func agentFilesForProfile(profile string) (dir, keyPath, cfgPath string, err error) {
	dir, err = config.DataDirForProfile(profile)
	if err != nil {
		return "", "", "", err
	}
	return dir, filepath.Join(dir, config.AgentKeyFile), filepath.Join(dir, config.ConfigFile), nil
}

func loadKey() (*identity.KeyPair, string, error) {
	_, keyPath, _, err := agentFiles()
	if err != nil {
		return nil, "", err
	}
	k, err := identity.Load(keyPath)
	if err != nil {
		return nil, "", err
	}
	return k, "key-" + string(k.ID()), nil
}

func loadKeyForProfile(profile string) (*identity.KeyPair, string, error) {
	_, keyPath, _, err := agentFilesForProfile(profile)
	if err != nil {
		return nil, "", err
	}
	k, err := identity.Load(keyPath)
	if err != nil {
		return nil, "", err
	}
	return k, "key-" + string(k.ID()), nil
}

func agentRelayURLForProfile(profile string) string {
	relayURL := config.DefaultRelayURL
	if _, _, cfgPath, err := agentFilesForProfile(profile); err == nil {
		if vals, _ := config.LoadAgentFile(cfgPath); vals["relay_url"] != "" {
			relayURL = vals["relay_url"]
		}
	}
	if v := config.EnvRelay(); v != "" {
		relayURL = v
	}
	return relayURL
}

// parseTTLDuration parses a TTL like "2h" into whole seconds.

func redactForDisplay(shareURL string) string {
	// Display the share link only through this interactive path; the raw
	// token is never logged elsewhere.
	return shareURL
}

// isTerminalStdout reports whether stdout is a real interactive
// terminal. A character-device check is not enough: pipes, sockets, and
// /dev/null can all present as char devices, and a secret shown on any
// of them lands in logs or captures. term.IsTerminal issues the actual
// terminal ioctl (A07).
func isTerminalStdout() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// writeShareLinkFile delivers the share capability to an explicitly
// requested file with owner-only permissions (A07). Empty path or empty
// share URL is a no-op. Callers enforce --no-share-link above.
