// WebSocket upgrade path (relay side). The public 101 is completed only
// after visitor authorization, route validation, and a successful local
// WebSocket handshake (E10). Thereafter bytes flow both directions subject
// to idle/max-lifetime timers, quotas, and cancellation (G04, G07).
package relay

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/limits"
	"ocliv/internal/metrics"
	"ocliv/internal/protocol"
)

// WSMaxLifetime bounds an upgraded connection. Read/write idle deadlines
// override any absolute deadline set on the conn, so the lifetime needs
// its own timer rather than SetDeadline (G04). It defaults to
// limits.WSMaxLifetime; tests may shorten it.
var WSMaxLifetime = limits.WSMaxLifetime

// serveWebSocket completes the public upgrade after the agent confirms the
// local 101 with a matching accept value, then bridges bytes both ways.
func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request, stream net.Conn, reqID string, t *routeTarget, sess *Session) {
	_ = reqID
	clientKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if clientKey == "" || !validWSVersion(r.Header.Get("Sec-WebSocket-Version")) {
		_ = sendAbort(stream, "bad_request", "invalid websocket handshake")
		http.Error(w, "invalid websocket handshake", http.StatusBadRequest)
		return
	}
	if _, err := base64.StdEncoding.DecodeString(clientKey); err != nil {
		_ = sendAbort(stream, "bad_request", "invalid websocket key")
		http.Error(w, "invalid websocket handshake", http.StatusBadRequest)
		return
	}
	expected := wsAccept(clientKey)

	// Wait for the agent's upgrade verdict with a bounded first-byte wait.
	if err := setStreamDeadline(stream, limits.FirstByteTimeout); err != nil {
		http.Error(w, "agent unreachable", http.StatusBadGateway)
		return
	}
	ftype, payload, err := protocol.ReadFrame(stream)
	_ = setStreamDeadline(stream, 0)
	if err != nil || ftype != protocol.FUpgradeAccept {
		http.Error(w, "websocket agent verdict missing", http.StatusBadGateway)
		return
	}
	var ua protocol.UpgradeAccept
	if err := json.Unmarshal(payload, &ua); err != nil {
		http.Error(w, "websocket agent verdict malformed", http.StatusBadGateway)
		return
	}
	if ua.Accept != expected {
		_ = sendAbort(stream, "bad_request", "websocket accept mismatch")
		http.Error(w, "websocket accept mismatch", http.StatusBadGateway)
		return
	}
	// The locally selected subprotocol must be one the visitor offered:
	// completing the public 101 with an unoffered protocol would bind
	// the visitor to terms it never agreed to (RFC 6455, P1-10).
	for k, v := range ua.Headers {
		if !strings.EqualFold(k, "Sec-WebSocket-Protocol") || v == "" {
			continue
		}
		if !wsSubprotocolOffered(r.Header.Get("Sec-WebSocket-Protocol"), v) {
			_ = sendAbort(stream, "bad_request", "websocket subprotocol not offered")
			http.Error(w, "websocket subprotocol mismatch", http.StatusBadGateway)
			return
		}
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = sendAbort(stream, "internal", "hijack unsupported")
		http.Error(w, "websocket not supported here", http.StatusInternalServerError)
		return
	}
	pubConn, bufrw, err := hj.Hijack()
	if err != nil {
		_ = sendAbort(stream, "internal", "hijack failed")
		http.Error(w, "websocket not supported here", http.StatusInternalServerError)
		return
	}
	defer pubConn.Close()
	// Forward bytes the server buffered past the handshake (a client
	// may pipeline frames immediately after its GET): the hijacked
	// bufrw owns those bytes and reading the raw conn would lose
	// them, corrupting the stream start.
	if err := drainHijackedBytes(bufrw, func(p []byte) error {
		return protocol.WriteFrame(stream, protocol.FUpgradeBytes, p)
	}); err != nil {
		_ = sendAbort(stream, "cancelled", "visitor went away")
		return
	}
	// Complete the public 101 (E10): only now, after auth + local 101.
	var hdr strings.Builder
	hdr.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	hdr.WriteString("Sec-WebSocket-Accept: " + expected + "\r\n")
	for k, v := range ua.Headers {
		ck := strings.ToLower(k)
		if ck == "sec-websocket-protocol" {
			hdr.WriteString("Sec-WebSocket-Protocol: " + v + "\r\n")
		}
	}
	hdr.WriteString("\r\n")
	if _, err := io.WriteString(pubConn, hdr.String()); err != nil {
		_ = sendAbort(stream, "cancelled", "visitor went away")
		return
	}
	metrics.Global.WSActive.Add(1)
	defer metrics.Global.WSActive.Add(-1)
	defer metrics.Global.WSClosed.Add(1)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// Max-lifetime enforcement needs its own timer: per-loop read/write
	// deadlines clobber any absolute conn deadline (G04).
	lifetime := time.AfterFunc(WSMaxLifetime, func() {
		_ = pubConn.SetDeadline(time.Now())
		_ = setStreamDeadline(stream, time.Millisecond)
		cancel()
	})
	defer lifetime.Stop()
	go func() {
		<-ctx.Done()
		_ = sendAbort(stream, "cancelled", "visitor went away")
		_ = pubConn.SetDeadline(time.Now())
		_ = setStreamDeadline(stream, time.Millisecond)
	}()
	// Public -> agent: frame raw bytes as UPGRADE_BYTES (bounded 64 KiB).
	// Both directions abort when the lease TTL lapses (R4).
	go func() {
		defer cancel()
		buf := make([]byte, 32*1024)
		for {
			if leaseExpired(t) {
				return
			}
			_ = pubConn.SetReadDeadline(time.Now().Add(limits.WSIdleTimeout))
			n, err := pubConn.Read(buf)
			if n > 0 {
				metrics.Global.BytesUp.Add(uint64(n))
				if werr := protocol.WriteFrame(stream, protocol.FUpgradeBytes, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	// Agent -> public: unframe UPGRADE_BYTES and write raw (E11 bidi).
	for {
		if leaseExpired(t) {
			return
		}
		ft, data, err := protocol.ReadFrame(stream)
		if err != nil {
			return
		}
		switch ft {
		case protocol.FUpgradeBytes:
			metrics.Global.BytesDown.Add(uint64(len(data)))
			_ = pubConn.SetWriteDeadline(time.Now().Add(limits.WSIdleTimeout))
			// Raw post-upgrade bytes bypass framing: a short write
			// must be completed, not truncated (P1-10).
			if err := protocol.WriteFull(pubConn, data); err != nil {
				return
			}
		case protocol.FClose, protocol.FAbort:
			return
		default:
			return
		}
	}
}

// drainHijackedBytes forwards bytes the HTTP server buffered past the
// upgrade handshake before Hijack returned. A client may pipeline
// WebSocket frames immediately after its GET; the hijacked bufrw owns
// those bytes and reading the raw conn would lose them. Empty buffers
// are a no-op so the common case adds no extra frame.
func drainHijackedBytes(bufrw *bufio.ReadWriter, forward func([]byte) error) error {
	n := bufrw.Reader.Buffered()
	if n == 0 {
		return nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(bufrw.Reader, buf); err != nil {
		return err
	}
	return forward(buf)
}

// wsAccept computes the RFC 6455 accept value.
func wsAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func validWSVersion(v string) bool {
	return strings.TrimSpace(v) == "13"
}

// wsSubprotocolOffered reports whether the locally selected subprotocol
// appears in the visitor's offer list. Tokens match exactly (RFC 6455
// treats them as case-sensitive); surrounding whitespace is ignored.
func wsSubprotocolOffered(offered, selected string) bool {
	for _, o := range strings.Split(offered, ",") {
		if strings.TrimSpace(o) == selected {
			return true
		}
	}
	return false
}
