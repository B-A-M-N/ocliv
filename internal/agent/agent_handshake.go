package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"ocliv/internal/protocol"
	"ocliv/internal/transport"
)

// Handshake phases extracted from Runner.once, which orchestrates them.
// Error strings are load-bearing: the CLI maps them through IsPermanent,
// so every message below must stay byte-identical to the original.

// fetchChallenge performs phase 1: fetch and decode the relay's one-time
// challenge. A denied challenge is classified before decode: 4xx (except
// 429) means the credential itself is bad and retrying cannot help (F09);
// 429/5xx stay retryable with backoff.
func (rn *Runner) fetchChallenge(httpClient *http.Client, relayURL string) (nonce []byte, nonceB64, origin, version string, err error) {
	chReq, _ := json.Marshal(map[string]string{"key_id": rn.KeyID})
	resp, err := httpClient.Post(relayURL+"/v1/agent/challenge", "application/json", strings.NewReader(string(chReq)))
	if err != nil {
		return nil, "", "", "", fmt.Errorf("relay unreachable: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		resp.Body.Close()
		return nil, "", "", "", fmt.Errorf("challenge temporarily unavailable (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, "", "", "", fmt.Errorf("enrollment revoked or unknown, stopping (status %d: %s)",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ch struct {
		Nonce   string `json:"nonce"`
		Origin  string `json:"origin"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&ch); err != nil {
		resp.Body.Close()
		return nil, "", "", "", fmt.Errorf("bad challenge: %w", err)
	}
	resp.Body.Close()
	nonce, err = base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("bad challenge nonce: %w", err)
	}
	return nonce, ch.Nonce, ch.Origin, ch.Version, nil
}

// buildHandshake performs phase 2: sign the canonical intent. Local
// readiness is re-probed at every (re)connect: the CLI probes only before
// the first run, and a hardcoded true would let a resume claim a
// reverified local service it never checked (P1-09).
func (rn *Runner) buildHandshake(nonce []byte, origin, version string) (intentRaw []byte, ts time.Time, sig []byte) {
	intentRaw, _ = json.Marshal(map[string]any{
		"port": rn.Cfg.Port, "name": rn.Cfg.Name, "public": rn.Cfg.Public,
		"ready": rn.leaseIntentReady(), "lease_id": rn.resumeLeaseID(),
		"ttl_seconds": rn.Cfg.TTLSeconds, "version": protocol.Version,
	})
	ts = time.Now().UTC()
	sig = rn.Key.Sign(nonce, origin, version, ts, string(intentRaw))
	return intentRaw, ts, sig
}

// dialAttach performs phases 3-4: open WSS with handshake headers, read
// the attached message, and validate it. The caller owns lease
// persistence, attach callbacks, and the yamux bridge, preserving once's
// original ordering. The relay closes denied attaches with distinct codes
// (F09): 4401 is terminal, anything else is retryable.
func (rn *Runner) dialAttach(ctx context.Context, httpClient *http.Client, wsBase string, nonceB64 string, intentRaw []byte, ts time.Time, sig []byte) (*websocket.Conn, Attached, error) {
	var att Attached
	wsURL := wsBase + "/v1/agent/connect"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, wsURL, nil)
	req.Header.Set("X-Ocliv-Key", rn.KeyID)
	req.Header.Set("X-Ocliv-Nonce", nonceB64)
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
		return nil, att, fmt.Errorf("agent session rejected: %w", err)
	}
	raw, err := transport.ReadControl(ctx, conn)
	if err != nil {
		conn.Close(websocket.StatusProtocolError, "no attach")
		if closeCode(err) == 4401 {
			return nil, att, fmt.Errorf("agent lease permanently denied by relay")
		}
		return nil, att, fmt.Errorf("no session attach: %w", err)
	}
	if err := json.Unmarshal(raw, &att); err != nil || att.Type != "attached" {
		conn.Close(websocket.StatusProtocolError, "bad attach")
		return nil, att, fmt.Errorf("bad session attach")
	}
	return conn, att, nil
}
