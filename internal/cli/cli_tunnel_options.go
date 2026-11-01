// Tunnel flag parsing and option validation.
package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
)

// parseTTLDuration parses a TTL like "2h" into whole seconds.
func parseTTLDuration(s string) (int64, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid ttl %q; try 2h", s)
	}
	// The protocol carries whole seconds with zero meaning no expiry: a
	// positive sub-second duration would truncate to an indefinite lease,
	// so it is rejected instead (P1-08).
	secs := int64(d.Seconds())
	if secs <= 0 {
		return 0, fmt.Errorf("invalid ttl %q; must be at least 1s", s)
	}
	return secs, nil
}

// attachEvents is the CLI-side sink for agent attachment callbacks. The
// runner invokes OnAttach on its networking path, so the callback must
// never block: it records the latest attachment and signals. Consumers
// observe every generation without stalling reconnects (P1-01). Rapid
// re-attachments coalesce; the latest lease ID and URL always win.

// tunnelOptions is the parsed tunnel invocation: validated flags with
// config-file/env precedence applied.
type tunnelOptions struct {
	cfg      config.Agent
	showJSON bool
	port     int
	// probePath/probeStatus declare the local readiness contract for
	// apps that don't answer usefully at / (Domain A). Empty path
	// means /; status 0 means any HTTP response counts.
	probePath   string
	probeStatus int
}

// tunnelReady is a validated tunnel invocation with enrollment loaded,
// the local target probed, and the runner constructed.

// parseTunnelOptions parses flags and applies config precedence
// (flags > non-secret env > config file > compiled defaults, A06). It
// returns a non-zero exit code after printing the operator-facing error
// for any invalid invocation.
func parseTunnelOptions(argv []string) (tunnelOptions, int) {
	var portStr string
	cfg := config.Agent{RelayURL: config.DefaultRelayURL}
	var showJSON bool
	var relayFlag, upstreamFlag, ttlFlag bool
	var probePath, probeStatusStr string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--public":
			cfg.Public = true
		case a == "--ipv6":
			cfg.IPv6 = true
		case a == "--name" && i+1 < len(argv):
			i++
			cfg.Name = strings.ToLower(argv[i])
		case strings.HasPrefix(a, "--name="):
			cfg.Name = strings.ToLower(strings.TrimPrefix(a, "--name="))
		case a == "--json":
			showJSON = true
		case a == "--no-share-link":
			cfg.NoShareLink = true
		case a == "--share-link-file" && i+1 < len(argv):
			i++
			cfg.ShareLinkFile = argv[i]
		case strings.HasPrefix(a, "--share-link-file="):
			cfg.ShareLinkFile = strings.TrimPrefix(a, "--share-link-file=")
		case a == "--upstream-host" && i+1 < len(argv):
			i++
			cfg.UpstreamHost = argv[i]
			upstreamFlag = true
		case strings.HasPrefix(a, "--upstream-host="):
			cfg.UpstreamHost = strings.TrimPrefix(a, "--upstream-host=")
			upstreamFlag = true
		case a == "--ttl" && i+1 < len(argv):
			i++
			secs, err := parseTTLDuration(argv[i])
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return tunnelOptions{}, apperr.ExitCLIValidation
			}
			cfg.TTLSeconds = secs
			ttlFlag = true
		case strings.HasPrefix(a, "--ttl="):
			secs, err := parseTTLDuration(strings.TrimPrefix(a, "--ttl="))
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return tunnelOptions{}, apperr.ExitCLIValidation
			}
			cfg.TTLSeconds = secs
			ttlFlag = true
		case a == "--relay" && i+1 < len(argv):
			i++
			cfg.RelayURL = argv[i]
			relayFlag = true
		case strings.HasPrefix(a, "--relay="):
			cfg.RelayURL = strings.TrimPrefix(a, "--relay=")
			relayFlag = true
		case a == "--probe-path" && i+1 < len(argv):
			i++
			probePath = argv[i]
		case strings.HasPrefix(a, "--probe-path="):
			probePath = strings.TrimPrefix(a, "--probe-path=")
		case a == "--probe-status" && i+1 < len(argv):
			i++
			probeStatusStr = argv[i]
		case strings.HasPrefix(a, "--probe-status="):
			probeStatusStr = strings.TrimPrefix(a, "--probe-status=")
		case strings.HasPrefix(a, "--"):
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return tunnelOptions{}, apperr.ExitCLIValidation
		case portStr == "":
			portStr = a
		default:
			fmt.Fprintln(os.Stderr, "unexpected argument "+a)
			return tunnelOptions{}, apperr.ExitCLIValidation
		}
	}
	port, err := config.ValidatePort(portStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error()+"; run `ocliv PORT` with 1-65535")
		return tunnelOptions{}, apperr.ExitCLIValidation
	}
	cfg.Port = port
	// Local readiness contract (Domain A): validated here, before any
	// network use. The agent re-probe reuses the same contract.
	var probeStatus int
	if probeStatusStr != "" {
		n, nerr := strconv.Atoi(probeStatusStr)
		if nerr != nil || n < 100 || n > 599 {
			fmt.Fprintln(os.Stderr, "error: --probe-status wants 100-599")
			return tunnelOptions{}, apperr.ExitCLIValidation
		}
		probeStatus = n
	}
	if probePath != "" {
		if verr := agent.ValidateProbePath(probePath); verr != nil {
			fmt.Fprintln(os.Stderr, "error: "+verr.Error())
			return tunnelOptions{}, apperr.ExitCLIValidation
		}
	}
	// Precedence: flags > non-secret env > config file > compiled defaults
	// (A06). Every accepted key has a live consumer (AS-057); a file-level
	// default_access_mode other than "protected" is rejected loudly rather
	// than remembered (A04).
	_, _, cfgPath, _ := agentFiles()
	fileVals, err := config.LoadAgentFile(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return tunnelOptions{}, apperr.ExitCLIValidation
	}
	if !relayFlag {
		if v := config.EnvRelay(); v != "" {
			cfg.RelayURL = v
		} else if fileVals["relay_url"] != "" {
			cfg.RelayURL = fileVals["relay_url"]
		}
	}
	if !upstreamFlag && fileVals["upstream_host"] != "" {
		cfg.UpstreamHost = fileVals["upstream_host"]
	}
	if !ttlFlag && fileVals["default_ttl"] != "" {
		secs, err := parseTTLDuration(fileVals["default_ttl"])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return tunnelOptions{}, apperr.ExitCLIValidation
		}
		cfg.TTLSeconds = secs
	}
	if m := fileVals["default_access_mode"]; m != "" && m != "protected" {
		fmt.Fprintf(os.Stderr, "error: default_access_mode %q not supported; tunnels default to protected\n", m)
		return tunnelOptions{}, apperr.ExitCLIValidation
	}
	// Fail fast on plaintext-to-network relay URLs instead of failing
	// obscurely at dial time (B01, B02). CheckRelayTLS is the single
	// policy: https everywhere, http only for loopback local development
	// (same rule as login and the agent dialer); remote plaintext is
	// rejected here, never at dial time.
	if err := config.CheckRelayTLS(cfg.RelayURL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return tunnelOptions{}, apperr.ExitCLIValidation
	}
	return tunnelOptions{cfg: cfg, showJSON: showJSON, port: port, probePath: probePath, probeStatus: probeStatus}, 0
}

// prepareTunnel loads enrollment, probes the local target, and constructs
// the runner. It returns a non-zero exit code after printing the
// operator-facing error when the tunnel cannot start.
