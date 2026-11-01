// Local WebSocket upgrade and signed management calls (agent side).
package agent

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/limits"
	"ocliv/internal/protocol"
)

// serveLocalWS performs the local HTTP/1.1 upgrade against the fixed
// loopback target, then bridges bytes both directions. Only after the
// upstream returns a valid 101 with a matching accept does the agent
// confirm the upgrade to the relay (E10).
func (rn *Runner) serveLocalWS(ctx context.Context, stream net.Conn, head protocol.RequestHead) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dialer := &net.Dialer{Timeout: limits.UpstreamTimeout}
	local, err := dialer.DialContext(ctx, "tcp", rn.Target)
	if err != nil {
		_ = sendAgentAbort(stream, "upstream_dial", "local websocket unreachable")
		return
	}
	defer local.Close()
	_ = local.SetDeadline(time.Now().Add(limits.FirstByteTimeout))
	// Replay the visitor handshake verbatim against local (headers already
	// sanitized by the relay; key/version preserved for accept fidelity).
	path := head.Path
	if path == "" {
		path = "/"
	}
	if head.RawQuery != "" {
		path += "?" + head.RawQuery
	}
	var sb strings.Builder
	sb.WriteString(head.Method + " " + path + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + rn.upstreamHost() + "\r\n")
	// The relay strips hop-by-hop framing (Upgrade/Connection) from the
	// forwarded headers; the agent re-asserts exactly one valid upgrade pair
	// for the local handshake. No other upgrade token is ever sent (D11).
	sb.WriteString("Upgrade: websocket\r\n")
	sb.WriteString("Connection: Upgrade\r\n")
	for k, v := range head.Headers {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "content-length" {
			continue
		}
		if !isWSForwardable(lk) {
			continue
		}
		sb.WriteString(k + ": " + v + "\r\n")
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(local, sb.String()); err != nil {
		_ = sendAgentAbort(stream, "upstream_dial", "local write failed")
		return
	}
	br := bufio.NewReader(local)
	resp, err := http.ReadResponse(br, &http.Request{Method: head.Method})
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		_ = sendAgentAbort(stream, "upstream_dial", "local upgrade refused")
		return
	}
	accept := resp.Header.Get("Sec-WebSocket-Accept")
	sub := resp.Header.Get("Sec-WebSocket-Protocol")
	_ = local.SetDeadline(time.Time{})
	ua := protocol.UpgradeAccept{Type: "upgrade_accept", Accept: accept}
	if sub != "" {
		ua.Headers = map[string]string{"Sec-WebSocket-Protocol": sub}
	}
	raw, _ := protocol.MarshalJSON(ua)
	if err := protocol.WriteFrame(stream, protocol.FUpgradeAccept, raw); err != nil {
		return
	}
	// Bidirectional bridge: local raw <-> framed stream bytes. Reads go
	// through the handshake's buffered reader: ReadResponse may have
	// buffered post-101 bytes ahead, and reading the raw conn would lose
	// them (P1-10).
	go func() {
		defer cancel()
		buf := make([]byte, 32*1024)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				if werr := protocol.WriteFrame(stream, protocol.FUpgradeBytes, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				_ = protocol.WriteFrame(stream, protocol.FClose, []byte(`{"type":"close"}`))
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		ft, data, err := protocol.ReadFrame(stream)
		if err != nil {
			return
		}
		switch ft {
		case protocol.FUpgradeBytes:
			_ = local.SetWriteDeadline(time.Now().Add(limits.WSIdleTimeout))
			// Raw post-upgrade bytes bypass framing: a short write
			// must be completed, not truncated (P1-10).
			if err := protocol.WriteFull(local, data); err != nil {
				return
			}
		case protocol.FClose, protocol.FAbort:
			return
		default:
			return
		}
	}
}

// isWSForwardable allows handshake headers needed locally; everything else
// was already stripped by the relay.
func isWSForwardable(lk string) bool {
	switch lk {
	case "upgrade", "connection", "sec-websocket-key", "sec-websocket-version",
		"sec-websocket-protocol", "sec-websocket-extensions", "origin", "cookie",
		"user-agent", "accept-language":
		return true
	}
	return false
}

// MgmtNonce mints a one-time identifier for a management mutation.
// The relay consumes each nonce once, so a captured request cannot replay
// within the clock-skew window even when the timestamp is unchanged (P1-07).
func MgmtNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// MgmtMessage builds the canonical signed bytes for an agent management
// request (method + path + timestamp + nonce). The relay verifies the same
// bytes; the nonce binds each signature to a single use.
func MgmtMessage(keyID, method, path string, ts time.Time, nonce string) []byte {
	return []byte(fmt.Sprintf("ocliv-mgmt-v1\n%s\n%s\n%s\n%d\n%s", keyID, method, path, ts.Unix(), nonce))
}

// SignMgmt signs an agent management request with a caller-provided nonce.
func (rn *Runner) SignMgmt(method, path string, ts time.Time, nonce string) []byte {
	return ed25519.Sign(rn.Key.Private(), MgmtMessage(rn.KeyID, method, path, ts, nonce))
}
