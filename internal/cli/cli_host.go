package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
)

// cmdHost is the single-command home-server orchestrator:
//
//	ocliv host PORT [--name N] [--auth ocliv-managed|upstream-oauth]
//	ocliv host --stdio --name N -- COMMAND [ARGS...]
//
// It verifies enrollment, registers a persistent systemd user service, starts
// it (with linger + enable for reboot persistence), and prints ready-to-paste
// client JSON snippets.
func cmdHost(argv []string) int {
	return cmdHostWithOps(argv, defaultServiceOps())
}

func cmdHostWithOps(argv []string, ops serviceOps) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv host PORT [--name N] [--auth ocliv-managed|upstream-oauth] | ocliv host --stdio --name N -- COMMAND...")
		return apperr.ExitCLIValidation
	}
	profile := config.ActiveProfile()
	if _, _, err := loadKeyForProfile(profile); err != nil {
		fmt.Fprintf(os.Stderr, "not enrolled in profile %q.\n", profile)
		fmt.Fprintln(os.Stderr, "Run `ocliv setup --auto --hostname YOUR_DOMAIN --acme-email YOU@EXAMPLE.COM` on your relay host,")
		fmt.Fprintln(os.Stderr, "or `ocliv login --relay https://YOUR_RELAY --code-file PATH` on this machine first.")
		return apperr.ExitAuth
	}

	var port int
	var stdio bool
	var name string
	auth := "ocliv-managed"
	var cmd []string

	i := 0
	if !strings.HasPrefix(argv[0], "-") {
		p, err := strconv.Atoi(argv[0])
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintf(os.Stderr, "invalid port %q (want 1-65535)\n", argv[0])
			return apperr.ExitCLIValidation
		}
		port = p
		i = 1
	}
	for ; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			cmd = argv[i+1:]
			break
		}
		switch {
		case a == "--stdio":
			stdio = true
		case a == "--name" || strings.HasPrefix(a, "--name="):
			v, ok := mcpFlagValue(argv, &i, "name")
			if !ok {
				return apperr.ExitCLIValidation
			}
			name = v
		case a == "--auth" || strings.HasPrefix(a, "--auth="):
			v, ok := mcpFlagValue(argv, &i, "auth")
			if !ok {
				return apperr.ExitCLIValidation
			}
			auth = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	if !stdio && port == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv host PORT [--name N] | ocliv host --stdio --name N -- COMMAND...")
		return apperr.ExitCLIValidation
	}
	if stdio && len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "ocliv host --stdio requires -- COMMAND [ARGS...]")
		return apperr.ExitCLIValidation
	}
	if name == "" {
		if stdio {
			fmt.Fprintln(os.Stderr, "ocliv host --stdio requires --name N")
			return apperr.ExitCLIValidation
		}
		name = fmt.Sprintf("mcp-%d", port)
	}

	addArgs := []string{name, "--type", "mcp", "--auth", auth}
	if stdio {
		addArgs = append(addArgs, "--stdio", "--")
		addArgs = append(addArgs, cmd...)
	} else {
		addArgs = append(addArgs, "--local", fmt.Sprintf("http://127.0.0.1:%d/mcp", port))
	}
	if code := cmdServiceAdd(addArgs, ops); code != apperr.ExitOK {
		return code
	}
	if code := cmdServiceStart([]string{name}, ops); code != apperr.ExitOK {
		return code
	}
	if st, err := openServicesForProfile(profile); err == nil {
		if rec, ok, _ := st.Get(name); ok && rec.PublicURL != "" {
			snippet, _ := json.MarshalIndent(map[string]any{
				"mcpServers": map[string]any{
					name: map[string]any{
						"url": rec.PublicURL,
					},
				},
			}, "", "  ")
			fmt.Printf("\nClaude Desktop / Cursor snippet:\n%s\n", string(snippet))
		}
	}
	return apperr.ExitOK
}
