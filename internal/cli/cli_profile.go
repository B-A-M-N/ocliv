package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/config"
)

func profileRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "ocliv"), nil
}

func cmdProfile(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv profile create NAME | use NAME|default | list")
		return apperr.ExitCLIValidation
	}
	root, err := profileRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	profiles := filepath.Join(root, "profiles")
	switch argv[0] {
	case "create":
		if len(argv) != 2 || !config.ValidProfileName(argv[1]) {
			fmt.Fprintln(os.Stderr, "usage: ocliv profile create NAME (lowercase letters, digits, hyphens; up to 32 characters)")
			return apperr.ExitCLIValidation
		}
		path := filepath.Join(profiles, argv[1])
		if err := os.MkdirAll(path, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "create profile: %v\n", err)
			return apperr.ExitInternal
		}
		fmt.Printf("Created profile %s\n", argv[1])
		return apperr.ExitOK
	case "use":
		if len(argv) != 2 {
			fmt.Fprintln(os.Stderr, "usage: ocliv profile use NAME|default")
			return apperr.ExitCLIValidation
		}
		name := argv[1]
		if name != "default" && !config.ValidProfileName(name) {
			fmt.Fprintln(os.Stderr, "invalid profile name")
			return apperr.ExitCLIValidation
		}
		if name != "default" {
			if _, err := os.Stat(filepath.Join(profiles, name)); err != nil {
				fmt.Fprintf(os.Stderr, "profile %q does not exist; create it with `ocliv profile create %s`\n", name, name)
				return apperr.ExitCLIValidation
			}
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitInternal
		}
		if name == "default" {
			if err := os.Remove(filepath.Join(root, "active-profile")); err != nil && !os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, err)
				return apperr.ExitInternal
			}
		} else {
			if err := os.WriteFile(filepath.Join(root, "active-profile"), []byte(name+"\n"), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return apperr.ExitInternal
			}
		}
		fmt.Printf("Active profile: %s\n", name)
		return apperr.ExitOK
	case "list":
		if len(argv) != 1 {
			fmt.Fprintln(os.Stderr, "usage: ocliv profile list")
			return apperr.ExitCLIValidation
		}
		fmt.Println("default")
		entries, err := os.ReadDir(profiles)
		if err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitInternal
		}
		for _, entry := range entries {
			if entry.IsDir() && config.ValidProfileName(entry.Name()) {
				fmt.Println(entry.Name())
			}
		}
		return apperr.ExitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown profile command %q\n", strings.TrimSpace(argv[0]))
		return apperr.ExitCLIValidation
	}
}
