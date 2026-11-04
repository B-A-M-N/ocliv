// Tunnel startup, attachment supervision, and steady-state execution.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
)

// attachEvents is the CLI-side sink for agent attachment callbacks. The
// runner invokes OnAttach on its networking path, so the callback must
// never block: it records the latest attachment and signals. Consumers
// observe every generation without stalling reconnects (P1-01). Rapid
// re-attachments coalesce; the latest lease ID and URL always win.
type attachEvents struct {
	mu     sync.Mutex
	latest agent.Attached
	// gen counts attachments; observed counts poll/next deliveries.
	// Delivery is generation-based, not token-based: the wakeup channel
	// may be consumed spuriously by a multiplexing select (P1-01), so a
	// consumed wakeup must never lose an undelivered attachment.
	gen      uint64
	observed uint64
	sig      chan struct{}
}

// newAttachEvents returns a sink whose callback never blocks: the signal
// channel is buffered and sends coalesce. Delivery is tracked by
// generation, so a slow first attachment is never lost when a multiplex
// select consumes the wakeup before poll runs.
func newAttachEvents() *attachEvents {
	return &attachEvents{sig: make(chan struct{}, 1)}
}

// onAttach records an attachment. Safe for the runner's networking
// goroutine: never blocks.
func (e *attachEvents) onAttach(a agent.Attached) {
	e.mu.Lock()
	e.latest = a
	e.gen++
	e.mu.Unlock()
	select {
	case e.sig <- struct{}{}:
	default:
	}
}

// current returns the latest attachment observed.
func (e *attachEvents) current() agent.Attached {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.latest
}

// next blocks until an attachment arrives or ctx ends.
func (e *attachEvents) next(ctx context.Context) (agent.Attached, bool) {
	for {
		if a, ok := e.poll(); ok {
			return a, true
		}
		select {
		case <-e.sig:
		case <-ctx.Done():
			return agent.Attached{}, false
		}
	}
}

// poll returns the latest attachment without blocking. Rapid
// re-attachments coalesce; use with wait to multiplex.
func (e *attachEvents) poll() (agent.Attached, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.observed == e.gen {
		return agent.Attached{}, false
	}
	e.observed = e.gen
	return e.latest, true
}

// wait reports attachment activity for multiplexing with other events.
// The wakeup may be spurious or consumed by a competing select branch;
// poll still delivers every generation exactly once.
func (e *attachEvents) wait() <-chan struct{} {
	return e.sig
}

// attachJSONMap builds the machine-readable attach record. Machine
// output is always secret-free (A07): the share link is a Bearer [REDACTED]
// and never appears here. It is delivered only to an interactive TTY or
// to an explicitly requested 0600 file (--share-link-file PATH).
func attachJSONMap(a agent.Attached) map[string]string {
	return map[string]string{
		"url": a.URL, "lease_id": a.LeaseID, "access_mode": a.AccessMode,
		"hostname": a.Hostname,
	}
}

// tunnelFailedHint is runnerExit's generic relay-reachability action. It
// is a constant so the named-relay variant can be derived from it
// without changing runnerExit's contract (existing callers and tests
// keep the same signature and exit codes).
const tunnelFailedHint = "tunnel failed: run `ocliv doctor`"

// runnerExit maps a terminal runner error to a stable exit code and a
// corrective action. A nil error (or a shutdown-driven one) is clean;
// definitive failures name the fix instead of hanging (P1-02).
func runnerExit(err error) (int, string) {
	if err == nil {
		return apperr.ExitCleanShutdown, ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "protocol_incompatible"):
		return apperr.ExitProtocol, "relay protocol mismatch: upgrade ocliv, then run `ocliv doctor`"
	case strings.Contains(msg, "must use https"):
		return apperr.ExitRelayTLS, "relay URL must be https:// (verified TLS required)"
	case strings.Contains(msg, "enrollment") || strings.Contains(msg, "revok") ||
		strings.Contains(msg, "permanently denied") || strings.Contains(msg, "auth"):
		return apperr.ExitAuth, "tunnel credential rejected: run `ocliv login --relay URL --code-file PATH` to re-enroll"
	default:
		return apperr.ExitRelayTLS, tunnelFailedHint
	}
}

// tunnelFailureHint maps a terminal runner error exactly like runnerExit
// but names the relay that was attempted in the generic reachability
// case. With more than one relay in play (OCLIV_RELAY_URL, a
// HOME-scoped agent config, an explicit --relay) the bare
// "tunnel failed" line leaves the operator unable to tell WHICH relay
// refused; exit codes and every specific hint stay unchanged.
func tunnelFailureHint(err error, relayURL string) (int, string) {
	code, hint := runnerExit(err)
	if hint == tunnelFailedHint && relayURL != "" {
		hint = fmt.Sprintf("tunnel failed for relay %s: run `ocliv doctor`", relayURL)
	}
	return code, hint
}

// relayNotConfirmedHint is the attach-timeout diagnostic. It names the
// relay that never confirmed the tunnel for the same reason: the
// operator must know where the connection was aimed.
func relayNotConfirmedHint(relayURL string) string {
	if relayURL == "" {
		return "relay did not confirm the tunnel; run `ocliv doctor`"
	}
	return fmt.Sprintf("relay %s did not confirm the tunnel; run `ocliv doctor`", relayURL)
}

// cmdTunnel implements `ocliv PORT`: probe local, connect, print URL.
func cmdTunnel(argv []string) int {
	opts, code := parseTunnelOptions(argv)
	if code != 0 {
		return code
	}
	ready, code := prepareTunnel(opts)
	if code != 0 {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, live, code, ok := runTunnel(ctx, ready)
	if !ok {
		return code
	}
	renderTunnelAttached(ready, a)
	a, code = runSteadyState(ctx, ready, live, a)
	return closeTunnel(ready, a, code)
}

// tunnelOptions is the parsed tunnel invocation: validated flags with
// config-file/env precedence applied.

// tunnelReady is a validated tunnel invocation with enrollment loaded,
// the local target probed, and the runner constructed.
type tunnelReady struct {
	opts   tunnelOptions
	target string
	dir    string
	key    *identity.KeyPair
	keyID  string
	runner *agent.Runner
}

// tunnelLive carries the running runner's event plumbing from startup
// sync into steady state.
type tunnelLive struct {
	events *attachEvents
	runErr chan error
}

// parseTunnelOptions parses flags and applies config precedence
// (flags > non-secret env > config file > compiled defaults, A06). It
// returns a non-zero exit code after printing the operator-facing error
// for any invalid invocation.

// prepareTunnel loads enrollment, probes the local target, and constructs
// the runner. It returns a non-zero exit code after printing the
// operator-facing error when the tunnel cannot start.
func prepareTunnel(opts tunnelOptions) (tunnelReady, int) {
	cfg := opts.cfg
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login --relay URL --code-file PATH` first")
		return tunnelReady{}, apperr.ExitAuth
	}
	target := config.LoopbackTarget(opts.port, cfg.IPv6)
	if perr := agent.ProbeLocalPath(target, opts.probePath, opts.probeStatus, 3*time.Second); perr != nil {
		fmt.Fprintf(os.Stderr, "local service unreachable at %s: %v\n", target, perr)
		return tunnelReady{}, apperr.ExitLocalTarget
	}
	dir, keyPath, _, _ := agentFiles()
	cfg.DataDir = dir
	cfg.KeyPath = keyPath
	// The reconnect re-probe reuses the startup contract (P1-09):
	// same path, same expected status, re-verified not redefined.
	rn := &agent.Runner{Cfg: cfg, Key: k, KeyID: keyID, Target: target,
		ProbePath: opts.probePath, ProbeStatus: opts.probeStatus}
	return tunnelReady{opts: opts, target: target, dir: dir, key: k, keyID: keyID, runner: rn}, 0
}

// runTunnel starts the runner and multiplexes the first attachment, a
// definitive runner failure, cancellation, and the attach timeout. A
// permanent failure fails fast with a corrective action instead of waiting
// out the timeout (P1-02).
func runTunnel(ctx context.Context, ready tunnelReady) (agent.Attached, *tunnelLive, int, bool) {
	events := newAttachEvents()
	ready.runner.OnAttach = events.onAttach
	showJSON := ready.opts.showJSON
	ready.runner.OnState = func(state string) {
		if state == "RECONNECTING" && !showJSON {
			fmt.Fprintln(os.Stderr, "… reconnecting (public traffic gets 503 until resume)")
		}
	}
	runErr := make(chan error, 1)
	go func() {
		runErr <- ready.runner.Run(ctx)
	}()
	live := &tunnelLive{events: events, runErr: runErr}
	var a agent.Attached
	attached := false
	startupTimer := time.NewTimer(45 * time.Second)
	defer startupTimer.Stop()
	for !attached {
		if ev, ok := events.poll(); ok {
			a, attached = ev, true
			break
		}
		select {
		case err := <-runErr:
			code, hint := tunnelFailureHint(err, ready.opts.cfg.RelayURL)
			if hint != "" {
				fmt.Fprintln(os.Stderr, hint)
			}
			return agent.Attached{}, nil, code, false
		case <-ctx.Done():
			return agent.Attached{}, nil, apperr.ExitCleanShutdown, false
		case <-events.wait():
		case <-startupTimer.C:
			if ev, ok := events.poll(); ok {
				a, attached = ev, true
				break
			}
			fmt.Fprintln(os.Stderr, relayNotConfirmedHint(ready.opts.cfg.RelayURL))
			return agent.Attached{}, nil, apperr.ExitRelayTLS, false
		}
	}
	return a, live, 0, true
}

// renderTunnelAttached persists the share link when requested and prints
// the honest attach lines (AS-023): the relay confirmed the route and the
// local HTTP probe passed. External DNS propagation and public-cert
// validity are verified by `ocliv doctor`, not claimed here.
func renderTunnelAttached(ready tunnelReady, a agent.Attached) {
	cfg := ready.opts.cfg
	showJSON := ready.opts.showJSON
	sharePath := cfg.ShareLinkFile
	if cfg.NoShareLink {
		if sharePath != "" {
			fmt.Fprintln(os.Stderr, "warning: --no-share-link suppresses --share-link-file")
		}
		sharePath = ""
	}
	if err := writeShareLinkFile(sharePath, a); err != nil {
		fmt.Fprintln(os.Stderr, "warning: "+err.Error())
	}
	if showJSON {
		_ = json.NewEncoder(os.Stdout).Encode(attachJSONMap(a))
		return
	}
	fmt.Println("✓ Tunnel attached (relay route ACTIVE)")
	fmt.Printf("✓ Local HTTP service responsive at %s\n", ready.target)
	if a.AccessMode == "public" {
		fmt.Println("! WARNING: visitor access is PUBLIC for this lease only")
	} else if a.AccessMode == "mcp_upstream_oauth" || a.AccessMode == "mcp_anonymous_fixture" {
		// Modes are relay constants (internal/relay/relay_mcp_ingress.go);
		// compared literally here so cli.go needs no relay import.
		fmt.Printf("✓ Access via MCP profile %s (enforced upstream, not by Ocliv visitor auth)\n", a.AccessMode)
	} else {
		fmt.Println("✓ Access protected")
	}
	fmt.Printf("✓ Forwarding localhost:%d\n\n", ready.opts.port)
	fmt.Println(a.URL)
	if a.ShareURL != "" && !cfg.NoShareLink {
		// A07: the share link is a Bearer [REDACTED] Print it only to a
		// verified interactive terminal. Piped output (logs, scripts)
		// gets a pointer instead; scripted use takes
		// --share-link-file PATH (0600). Machine-readable --json
		// output never carries it.
		if isTerminalStdout() {
			fmt.Println("Share link: " + redactForDisplay(a.ShareURL))
		} else {
			fmt.Println("Share link withheld: stdout is not a terminal (use --share-link-file PATH).")
		}
	}
	fmt.Println("Press Ctrl+C to close this ephemeral tunnel.")
}

// runSteadyState drains re-attachments so reconnects never block the
// runner, keeping the current lease ID and URL across valid reconnections
// (P1-01). Machine-readable output stays stable: only the first attachment
// prints. A runner that exits on its own is a terminal failure, not a
// clean shutdown (P1-02).
func runSteadyState(ctx context.Context, ready tunnelReady, live *tunnelLive, a agent.Attached) (agent.Attached, int) {
	showJSON := ready.opts.showJSON
	exitCode := apperr.ExitCleanShutdown
steady:
	for {
		if ra, ok := live.events.poll(); ok {
			// Keep the latest authoritative attachment: shutdown must
			// close the live lease even when its file never persisted.
			a = ra
			if !showJSON {
				fmt.Fprintf(os.Stderr, "✓ Re-attached (generation %d) %s\n", ra.Generation, ra.URL)
			}
			continue
		}
		select {
		case err := <-live.runErr:
			if ctx.Err() != nil {
				break steady
			}
			code, hint := tunnelFailureHint(err, ready.opts.cfg.RelayURL)
			if hint != "" {
				fmt.Fprintln(os.Stderr, hint)
			}
			exitCode = code
			break steady
		case <-ctx.Done():
			break steady
		case <-live.events.wait():
		}
	}
	return a, exitCode
}

// CleanupResult records remote revocation outcomes independently: local
// shutdown and remote revocation are different results, and a failed
// remote close must never present as a clean exit (P1-8). Status -1
// means the operation was not attempted; 0 means the relay was
// unreachable (mgmtCall transport failure). Details are trimmed relay
// error strings, never secrets.
