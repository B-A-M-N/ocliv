// Visitor access management: share, rotate, revoke.
package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
)

// resolveAccessTarget resolves a lease ID explicitly by service NAME or --lease,
// refusing to implicitly pick "most recently updated" when multiple services/leases exist.
func resolveAccessTarget(name, leaseFlag, dataDir string) (leaseID, displayTarget string, err error) {
	if leaseFlag != "" {
		return leaseFlag, leaseFlag, nil
	}
	if name != "" {
		if svcStore, serr := openServices(); serr == nil {
			if rec, ok, gerr := svcStore.Get(name); gerr == nil && ok {
				if rec.LeaseID == "" {
					return "", name, fmt.Errorf("service %q has no active HTTP lease ID (start it first)", name)
				}
				return rec.LeaseID, rec.Name, nil
			}
		}
		if ls, lerr := config.OpenLeaseStore(dataDir); lerr == nil {
			want := canonicalHTTPLabel(name)
			var matches []config.LeaseRecord
			for _, r := range ls.List() {
				if r.LeaseID == name || strings.ToLower(r.Name) == want {
					matches = append(matches, r)
				}
			}
			if len(matches) == 1 {
				return matches[0].LeaseID, name, nil
			}
			if len(matches) > 1 {
				return "", name, fmt.Errorf("ambiguous target %q (%d matching leases); specify --lease ID", name, len(matches))
			}
		}
		return "", name, fmt.Errorf("unknown service or lease %q", name)
	}
	// No explicit target: permit implicit selection ONLY when exactly one lease exists.
	ls, lerr := config.OpenLeaseStore(dataDir)
	if lerr != nil {
		return "", "", fmt.Errorf("no active lease; start a tunnel or hosted service first")
	}
	recs := ls.List()
	if len(recs) == 0 {
		return "", "", fmt.Errorf("no active lease; start a tunnel or hosted service first")
	}
	if len(recs) > 1 {
		return "", "", fmt.Errorf("multiple active leases (%d); specify NAME or --lease ID explicitly", len(recs))
	}
	disp := recs[0].Name
	if disp == "" {
		disp = recs[0].LeaseID
	}
	return recs[0].LeaseID, disp, nil
}

// cmdShare is the everyday top-level alias for `ocliv access share`.
func cmdShare(argv []string) int {
	return cmdAccess(append([]string{"share"}, argv...))
}

// cmdAccess manages visitor credentials (share/rotate/revoke) safely:
//   - Explicit target resolution (never implicitly picks latest among multiple services)
//   - `--confirm TARGET` required for destructive `revoke`
//   - Raw share links / access tokens are only displayed to a real TTY or written
//     to an owner-only `--out PATH` file (0600); `--json` emits metadata only.
func cmdAccess(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv access share|rotate|revoke [NAME] [--lease ID] [--out PATH] [--confirm TARGET] [--json]")
		return apperr.ExitCLIValidation
	}
	action := argv[0]
	if action != "share" && action != "rotate" && action != "revoke" {
		fmt.Fprintf(os.Stderr, "unknown access command %q\n", action)
		return apperr.ExitCLIValidation
	}
	var name, leaseFlag, outPath, confirm, profileFlag string
	var jsonOut bool
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--profile" || strings.HasPrefix(a, "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profileFlag = v
		case a == "--lease" || strings.HasPrefix(a, "--lease="):
			v, ok := mcpFlagValue(argv, &i, "lease")
			if !ok {
				return apperr.ExitCLIValidation
			}
			leaseFlag = v
		case a == "--out" || strings.HasPrefix(a, "--out="):
			v, ok := mcpFlagValue(argv, &i, "out")
			if !ok {
				return apperr.ExitCLIValidation
			}
			outPath = v
		case a == "--confirm" || strings.HasPrefix(a, "--confirm="):
			v, ok := mcpFlagValue(argv, &i, "confirm")
			if !ok {
				return apperr.ExitCLIValidation
			}
			confirm = v
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "unknown access flag %q\n", a)
			return apperr.ExitCLIValidation
		case name == "":
			name = a
		default:
			fmt.Fprintf(os.Stderr, "unexpected argument %q\n", a)
			return apperr.ExitCLIValidation
		}
	}

	if profileFlag != "" {
		prevProf := os.Getenv("OCLIV_PROFILE")
		_ = os.Setenv("OCLIV_PROFILE", profileFlag)
		defer func() {
			if prevProf == "" {
				_ = os.Unsetenv("OCLIV_PROFILE")
			} else {
				_ = os.Setenv("OCLIV_PROFILE", prevProf)
			}
		}()
	}

	// P0-7: JSON mode for secret-bearing operations (share/rotate) MUST
	// require --out PATH before making any relay mutation, otherwise a
	// one-use share link or rotated token would be burned and discarded.
	if (action == "share" || action == "rotate") && jsonOut && outPath == "" {
		fmt.Fprintf(os.Stderr, "error: `ocliv access %s --json` requires `--out PATH` so the minted credential is not discarded\n", action)
		return apperr.ExitCLIValidation
	}
	// Secret-bearing actions in non-TTY mode require --out PATH so bearer
	// credentials are never dumped into CI/pipeline logs. Uses real TTY
	// detection (term.IsTerminal) rather than ModeCharDevice.
	if (action == "share" || action == "rotate") && outPath == "" && !jsonOut && !isTerminalStdout() {
		fmt.Fprintf(os.Stderr, "error: refusing to print raw bearer credential to non-TTY stdout; pass `--out PATH` (mode 0600)\n")
		return apperr.ExitCLIValidation
	}

	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	dir, _, cfgPath, _ := agentFiles()
	relayURL := config.DefaultRelayURL
	if vals, _ := config.LoadAgentFile(cfgPath); vals["relay_url"] != "" {
		relayURL = vals["relay_url"]
	}
	if v := config.EnvRelay(); v != "" {
		relayURL = v
	}

	leaseID, targetLabel, err := resolveAccessTarget(name, leaseFlag, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	if action == "revoke" && confirm != targetLabel && confirm != leaseID {
		fmt.Fprintf(os.Stderr, "error: destructive access revoke requires `--confirm %s`\n", targetLabel)
		return apperr.ExitCLIValidation
	}

	// P0-6: `access revoke` invokes visitor-only credential revocation
	// (/access/revoke), keeping the lease and publication alive.
	endpointAction := action
	if action == "revoke" {
		endpointAction = "access/revoke"
	}
	code, body, err := mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/lease/"+leaseID+"/"+endpointAction)
	if err != nil {
		fmt.Fprintf(os.Stderr, "access %s relay transport failed: %v\n", action, err)
		return apperr.ExitRelayTLS
	}
	if code != http.StatusOK {
		fmt.Fprintf(os.Stderr, "access %s failed (relay status %d)\n", action, code)
		return apperr.ExitAuth
	}

	var parsed map[string]string
	_ = json.Unmarshal(body, &parsed)
	secretVal := ""
	if action == "share" {
		secretVal = parsed["share_url"]
	} else if action == "rotate" {
		secretVal = parsed["access_token"]
	}
	if outPath != "" && secretVal != "" {
		if werr := writeAtomic0600(outPath, secretVal+"\n"); werr != nil {
			fmt.Fprintf(os.Stderr, "error writing credential file %s: %v\n", outPath, werr)
			return apperr.ExitInternal
		}
	}
	if jsonOut {
		// JSON output contains metadata ONLY, never raw bearer credentials.
		meta := map[string]any{
			"action":           action,
			"target":           targetLabel,
			"lease_id":         leaseID,
			"status":           "ok",
			"credential_saved": outPath != "" && secretVal != "",
		}
		if outPath != "" {
			meta["out_path"] = outPath
		}
		b, _ := json.MarshalIndent(meta, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	if outPath != "" && secretVal != "" {
		fmt.Printf("✓ %s succeeded for %s (lease %s); credential written to %s (mode 0600)\n", action, targetLabel, leaseID, outPath)
		return apperr.ExitOK
	}
	if secretVal != "" {
		fmt.Println(secretVal)
		return apperr.ExitOK
	}
	fmt.Printf("✓ %s succeeded for %s (lease %s)\n", action, targetLabel, leaseID)
	return apperr.ExitOK
}
