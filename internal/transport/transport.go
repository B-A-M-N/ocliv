// Package transport glues the WSS carrier to yamux multiplexed streams
// (spec 3.1). The agent dials outbound WSS and serves yamux; the relay
// accepts the WSS and opens one stream per authorized request.
// permessage-deflate is disabled: stream payloads may carry secrets and
// compression complicates flow control and memory safety.
//
// Handshake control (challenge JSON + attached JSON) travels as Text
// messages before either side bridges the connection to yamux; the
// NetConn bridge only ever sees Binary messages afterwards.
package transport

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"ocliv/internal/apperr"
)

// ReadLimit bounds a single websocket message used for the NetConn bridge.
const ReadLimit = 1 << 20 // 1 MiB; yamux frames are far smaller

// ControlReadLimit bounds handshake Text messages (challenge/attached).
const ControlReadLimit = 32 * 1024

// checkedTLS refuses nil configs and InsecureSkipVerify (B01, B02).
// loopbackPlaintext permits direct-HTTP tests where the relay is dialed over
// plaintext loopback (local OS isolation is the trusted ingress there).
func checkedTLS(tlsCfg *tls.Config, url string, loopbackPlaintext bool) (*tls.Config, bool, error) {
	if isWSS(url) {
		if tlsCfg == nil || tlsCfg.InsecureSkipVerify {
			return nil, false, apperr.E(apperr.CodeTLSVerify, "refusing WSS dial without verified TLS", nil)
		}
		return tlsCfg, true, nil
	}
	if !loopbackPlaintext {
		return nil, false, apperr.E(apperr.CodeTLSVerify, "agent requires wss:// relay URL", nil)
	}
	return nil, false, nil
}

func isWSS(url string) bool {
	return len(url) > 6 && (url[:6] == "wss://" || url[:5] == "https")
}

// DialWS opens a verified WSS (or test loopback WS) connection without
// bridging it; the caller performs the handshake then bridges.
func DialWS(ctx context.Context, url string, tlsCfg *tls.Config, loopbackPlaintext bool) (*websocket.Conn, error) {
	tcfg, useTLS, err := checkedTLS(tlsCfg, url, loopbackPlaintext)
	if err != nil {
		return nil, err
	}
	var hc *http.Client
	if useTLS {
		hc = &http.Client{Transport: &http.Transport{TLSClientConfig: tcfg}}
	}
	wsURL := url
	opts := &websocket.DialOptions{HTTPClient: hc, CompressionMode: websocket.CompressionDisabled}
	conn, _, err := websocket.Dial(ctx, wsURL, opts)
	if err != nil {
		return nil, apperr.E(apperr.CodeRelayUnreach, "websocket dial to relay failed", err)
	}
	return conn, nil
}

// BridgeServer wraps an established agent-side connection in a yamux server
// session (agent accepts streams).
func BridgeServer(ctx context.Context, conn *websocket.Conn) (net.Conn, error) {
	return websocket.NetConn(ctx, conn, websocket.MessageBinary), nil
}

// WriteControl sends one bounded Text control message.
func WriteControl(ctx context.Context, conn *websocket.Conn, payload []byte) error {
	if len(payload) > ControlReadLimit {
		return apperr.E(apperr.CodeSizeLimit, "control message exceeds cap", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, payload)
}

// OpenStream opens one bounded stream for a single authorized request.
// Admission control must already have run (G02). Callers must Close the
// stream to release window/memory (E06).
func OpenStream(sess *yamux.Session) (net.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := sess.OpenStream()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, apperr.E(apperr.CodeCapacity, "opening multiplexed stream", r.err)
		}
		if r.c == nil {
			return nil, apperr.E(apperr.CodeCapacity, "stream admission failed", nil)
		}
		return r.c, nil
	case <-time.After(10 * time.Second):
		return nil, apperr.E(apperr.CodeCapacity, "stream admission timed out", nil)
	}
}

// ReadControl reads one bounded Text control message.
func ReadControl(ctx context.Context, conn *websocket.Conn) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	typ, payload, err := conn.Read(ctx)
	if err != nil {
		return nil, apperr.E(apperr.CodeProtocol, "reading control message", err)
	}
	if typ != websocket.MessageText {
		return nil, apperr.E(apperr.CodeProtocol, "expected text control message", nil)
	}
	if len(payload) > ControlReadLimit {
		return nil, apperr.E(apperr.CodeSizeLimit, "control message exceeds cap", nil)
	}
	return payload, nil
}
