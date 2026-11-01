// Package agent is the local tunnel agent: it probes the local service,
// authenticates to the relay over verified TLS, serves multiplexed streams
// from exactly one configured loopback destination, and reconnects with
// bounded backoff and jitter (F09). It never listens inbound (A02).
package agent

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/protocol"
	"ocliv/internal/transport"
)

// Attached is the relay's session confirmation.
type Attached struct {
	Type       string `json:"type"`
	SessionID  string `json:"session_id"`
	LeaseID    string `json:"lease_id"`
	Hostname   string `json:"hostname"`
	Generation uint64 `json:"generation"`
	AccessMode string `json:"access_mode"`
	URL        string `json:"url"`
	ShareURL   string `json:"share_url,omitempty"`
}

// Runner holds agent runtime state.
type Runner struct {
	Cfg      config.Agent
	Key      *identity.KeyPair
	KeyID    string
	Target   string // literal loopback:port (D06)
	Upstream string // Host to present locally (D09)
	OnAttach func(a Attached)
	OnState  func(state string) // CONNECTED / RECONNECTING
	HTTP     *http.Client       // test hook: local upstream client
	WSURL    string             // test hook: ws base for upgrades (unused, raw TCP used)
	// HandshakeTransport overrides the agent handshake transport
	// (challenge POST + WSS dial). Test hook only: lets a harness
	// present the public relay authority while dialing loopback.
	// nil preserves production behavior exactly.
	HandshakeTransport http.RoundTripper

	mu         sync.Mutex
	httpShared *http.Client // loopback client shared across streams (P2-1)
}

// ProbeLocal verifies a responsive local HTTP service. Any HTTP status
// proves a listener; connection failure does not (F06 honest reporting).
// Only an actual HTTP response counts: a bare TCP listener with no HTTP
// stack is not local readiness (AS-023).
func ProbeLocal(target string, timeout time.Duration) error {
	// Redirects are not followed: a redirect is itself proof of a local
	// HTTP listener, and following it could report a foreign service as
	// local readiness (R3).
	c := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := c.Get("http://" + target + "/")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Run connects, serves, and reconnects until ctx ends. Permanent credential
// or protocol failures stop retries and require corrective action (F09).
func (rn *Runner) Run(ctx context.Context) error {
	// Release the shared loopback pool at true shutdown; reconnects
	// reuse it.
	defer rn.closeIdleLocalConns()
	backoff := 250 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		err := rn.once(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if IsPermanent(err) {
			return err
		}
		if rn.OnState != nil {
			rn.OnState("RECONNECTING")
		}
		// Bounded exponential backoff with jitter (F09).
		jitter := time.Duration(float64(backoff) * 0.2 * rand01())
		wait := backoff + jitter
		if wait > maxBackoff {
			wait = maxBackoff
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// leaseIntentReady re-probes the local HTTP service for the lease
// intent. Any HTTP status counts as responsive (same as the CLI
// pre-probe); only reachability is re-verified (P1-09).
func (rn *Runner) leaseIntentReady() bool {
	if rn.Target == "" {
		return false
	}
	return ProbeLocal(rn.Target, 3*time.Second) == nil
}

// PermanentError marks a definitive runner failure that retries cannot
// fix (bad credentials, revocation, TLS policy). Retry classification
// follows this type through errors.As — including through fmt %w chains —
// never message wording, so a wording edit cannot silently change retry
// behavior (audit P2). Messages stay human-readable and byte-identical
// to the historical strings the CLI maps to corrective actions.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps a definitive failure for IsPermanent.
func Permanent(err error) error { return &PermanentError{Err: err} }

// IsPermanent reports whether a runner error is a definitive failure
// that retries cannot fix. The CLI uses it to fail fast with a
// corrective action instead of waiting out a reconnect timeout (P1-02).
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	var perm *PermanentError
	return errors.As(err, &perm)
}

// wsBaseFor maps a relay URL to its agent transport base. Plaintext is a
// downgrade and is allowed only for loopback destinations; anything else
// must use https, otherwise enrollment and handshake secrets would travel
// in the clear (B01, B02).
func wsBaseFor(relayURL string) (string, error) {
	if err := config.CheckRelayTLS(relayURL); err != nil {
		return "", err
	}
	t := strings.TrimRight(relayURL, "/")
	if strings.HasPrefix(t, "https://") {
		return "wss://" + strings.TrimPrefix(t, "https://"), nil
	}
	return "ws://" + strings.TrimPrefix(t, "http://"), nil
}

// closeCode extracts the WebSocket close code from a control-read failure,
// or 0 when the failure carries no close code.
func closeCode(err error) int {
	var cerr websocket.CloseError
	if errors.As(err, &cerr) {
		return int(cerr.Code)
	}
	return 0
}

// once performs one session: challenge, signed handshake, attach, serve.
func (rn *Runner) once(ctx context.Context) error {
	relayURL := strings.TrimRight(rn.Cfg.RelayURL, "/")
	wsBase, err := wsBaseFor(relayURL)
	if err != nil {
		return Permanent(err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// Lab/private relay edges: trust the OCLIV_CACERT bundle in
	// addition to system roots. Unset keeps default verification;
	// a broken bundle fails the run, never silently downgrades it.
	if pool, err := config.CertPool(); err != nil {
		return fmt.Errorf("bad CA bundle: %w", err)
	} else if pool != nil {
		tlsCfg.RootCAs = pool
	}
	httpClient := &http.Client{Timeout: 15 * time.Second}
	if strings.HasPrefix(relayURL, "https") {
		httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	if rn.HandshakeTransport != nil {
		httpClient.Transport = rn.HandshakeTransport
	}
	// 1. Fetch one-time challenge.
	chReq, _ := json.Marshal(map[string]string{"key_id": rn.KeyID})
	resp, err := httpClient.Post(relayURL+"/v1/agent/challenge", "application/json", strings.NewReader(string(chReq)))
	if err != nil {
		return fmt.Errorf("relay unreachable: %w", err)
	}
	// A denied challenge is classified before decode: 4xx (except 429)
	// means the credential itself is bad and retrying cannot help (F09:
	// stop on permanent credential failure, same as the WS 4401 path).
	// 429/5xx stay retryable with backoff.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		resp.Body.Close()
		return fmt.Errorf("challenge temporarily unavailable (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return Permanent(fmt.Errorf("enrollment revoked or unknown, stopping (status %d: %s)",
			resp.StatusCode, strings.TrimSpace(string(body))))
	}
	var ch struct {
		Nonce   string `json:"nonce"`
		Origin  string `json:"origin"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&ch); err != nil {
		resp.Body.Close()
		return fmt.Errorf("bad challenge: %w", err)
	}
	resp.Body.Close()
	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		return fmt.Errorf("bad challenge nonce: %w", err)
	}
	// 2. Sign the canonical intent.
	// Re-probe local readiness at every (re)connect: the CLI probes
	// only before the first run, and a hardcoded true would let a
	// resume claim a reverified local service it never checked (P1-09).
	intentRaw, _ := json.Marshal(map[string]any{
		"port": rn.Cfg.Port, "name": rn.Cfg.Name, "public": rn.Cfg.Public,
		"access_mode": rn.Cfg.AccessMode,
		"ready":       rn.leaseIntentReady(), "lease_id": rn.resumeLeaseID(),
		"ttl_seconds": rn.Cfg.TTLSeconds, "version": protocol.Version,
	})
	ts := time.Now().UTC()
	sig := rn.Key.Sign(nonce, ch.Origin, ch.Version, ts, string(intentRaw))
	// 3. Open WSS with handshake headers.
	wsURL := wsBase + "/v1/agent/connect"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, wsURL, nil)
	req.Header.Set("X-Ocliv-Key", rn.KeyID)
	req.Header.Set("X-Ocliv-Nonce", ch.Nonce)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Intent", base64.StdEncoding.EncodeToString(intentRaw))
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	dialOpts := &websocket.DialOptions{
		HTTPClient:      httpClient,
		HTTPHeader:      req.Header,
		CompressionMode: websocket.CompressionDisabled,
	}
	conn, _, err := websocket.Dial(ctx, wsURL, dialOpts)
	if err != nil {
		return fmt.Errorf("agent session rejected: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")
	// 4. Read the attached message, then bridge to yamux server.
	raw, err := transport.ReadControl(ctx, conn)
	if err != nil {
		conn.Close(websocket.StatusProtocolError, "no attach")
		// The relay closes denied attaches with distinct codes (F09):
		// 4401 is terminal, anything else is retryable.
		if closeCode(err) == 4401 {
			return Permanent(fmt.Errorf("agent lease permanently denied by relay"))
		}
		return fmt.Errorf("no session attach: %w", err)
	}
	var att Attached
	if err := json.Unmarshal(raw, &att); err != nil || att.Type != "attached" {
		conn.Close(websocket.StatusProtocolError, "bad attach")
		return fmt.Errorf("bad session attach")
	}
	if err := rn.saveLease(att); err != nil {
		conn.Close(websocket.StatusInternalError, "lease persist failed")
		return fmt.Errorf("persisting lease state: %w", err)
	}
	if rn.OnState != nil {
		rn.OnState("CONNECTED")
	}
	if rn.OnAttach != nil {
		rn.OnAttach(att)
	}
	netConn := websocket.NetConn(context.Background(), conn, websocket.MessageBinary)
	ys, err := yamux.Server(netConn, yamux.DefaultConfig())
	if err != nil {
		return fmt.Errorf("multiplex failed: %w", err)
	}
	defer ys.Close()
	return rn.serve(ctx, ys, att)
}
