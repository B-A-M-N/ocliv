// WebSocket end-to-end over the tunnel: bidirectional echo while HTTP
// traffic stays responsive.
package integration

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func wsDial(t *testing.T, h *harness, cookie string) *websocket.Conn {
	return wsDialPath(t, h, cookie, "/ws")
}

func wsDialPath(t *testing.T, h *harness, cookie, wsPath string) *websocket.Conn {
	t.Helper()
	// Dial the lease hostname; override transport dial to reach the test
	// server listener regardless of URL host.
	addr := h.relaySrv.Listener.Addr().String()
	wsURL := "ws://" + h.host() + ":" + testPort(h) + wsPath
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			},
		},
	}
	opts := &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: http.Header{
			"Cookie": []string{cookie},
			// Exact same-origin proof, including the (test-only) port,
			// matching tunnelOrigin() semantics (C09).
			"Origin": []string{"http://" + h.host() + ":" + testPort(h)},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, opts)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	// Test-only large-message allowance; product streams in 64 KiB frames.
	c.SetReadLimit(4 << 20)
	return c
}

func testPort(h *harness) string {
	_, port, err := net.SplitHostPort(h.relaySrv.Listener.Addr().String())
	if err != nil {
		panic(err)
	}
	return port
}

func TestWebSocketBidirectional(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	conn := wsDial(t, h, cookie)
	defer conn.Close(websocket.StatusNormalClosure, "")
	ctx := context.Background()
	// Bidirectional echo.
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("ws-msg-%d", i)
		if err := conn.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
			t.Fatalf("ws write: %v", err)
		}
		_, got, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("ws read: %v", err)
		}
		if string(got) != msg {
			t.Fatalf("ws echo mismatch: %q", got)
		}
	}
	// HTTP stays responsive while WS is open (no head-of-line block, E15).
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("http during ws: status=%d body=%q", resp.StatusCode, body)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := conn.Write(ctx, websocket.MessageBinary, bytes_Repeat("b", 1<<20)); err != nil {
			t.Errorf("ws binary write: %v", err)
		}
	}()
	_, got, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("ws binary read: %v", err)
	}
	if len(got) != 1<<20 {
		t.Fatalf("ws binary echo: %d bytes", len(got))
	}
	wg.Wait()
}

func TestWebSocketImmediateServerMessage(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	conn := wsDialPath(t, h, cookie, "/ws-immediate")
	defer conn.Close(websocket.StatusNormalClosure, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// The server speaks first: bytes coalesced with the 101 handshake
	// must not be lost in the tunnel.
	_, got, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("ws immediate read: %v", err)
	}
	if string(got) != "immediate-hello" {
		t.Fatalf("ws immediate mismatch: %q", got)
	}
}

// wsHandshakeRaw performs a raw WebSocket handshake so the test controls
// the offered subprotocols exactly. Returns the status line and headers.
func wsHandshakeRaw(t *testing.T, h *harness, cookie, wsPath, offer string) (string, http.Header) {
	t.Helper()
	addr := h.relaySrv.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	key := base64.StdEncoding.EncodeToString(bytes_Repeat("k", 16))
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\nHost: %s:%s\r\n", wsPath, h.host(), testPort(h))
	fmt.Fprintf(&sb, "Upgrade: websocket\r\nConnection: Upgrade\r\n")
	fmt.Fprintf(&sb, "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", key)
	fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
	fmt.Fprintf(&sb, "Origin: http://%s:%s\r\n", h.host(), testPort(h))
	if offer != "" {
		fmt.Fprintf(&sb, "Sec-WebSocket-Protocol: %s\r\n", offer)
	}
	sb.WriteString("\r\n")
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		t.Fatal(err)
	}
	// Read the response headers only: a 101 upgrade holds the
	// connection open, so reading to EOF would hang.
	br := bufio.NewReader(io.LimitReader(conn, 16<<10))
	var lines []string
	for len(lines) < 100 {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("ws handshake read: %v", err)
		}
		l = strings.TrimSuffix(strings.TrimSuffix(l, "\n"), "\r")
		if l == "" {
			break
		}
		lines = append(lines, l)
	}
	if len(lines) == 0 {
		t.Fatal("ws handshake: empty response")
	}
	status := lines[0]
	lines = lines[1:]
	hdr := http.Header{}
	for _, l := range lines {
		if i := strings.Index(l, ":"); i > 0 {
			hdr.Add(strings.TrimSpace(l[:i]), strings.TrimSpace(l[i+1:]))
		}
	}
	return status, hdr
}

func TestWebSocketSubprotocolMismatchRejected(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	// Visitor offers "chat", local backend selects "evil": the relay
	// must not complete the upgrade with an unoffered protocol.
	status, _ := wsHandshakeRaw(t, h, cookie, "/ws-sub?select=evil", "chat")
	if !strings.Contains(status, "502") {
		t.Fatalf("subprotocol mismatch: want 502, got %q", status)
	}
}

func TestWebSocketSubprotocolMatchAccepted(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	// Visitor offers "chat", local backend selects "chat": the 101 must
	// carry the negotiated protocol back.
	status, hdr := wsHandshakeRaw(t, h, cookie, "/ws-sub?select=chat", "chat")
	if !strings.Contains(status, "101") {
		t.Fatalf("subprotocol match: want 101, got %q", status)
	}
	if got := hdr.Get("Sec-WebSocket-Protocol"); got != "chat" {
		t.Fatalf("subprotocol match: header = %q, want chat", got)
	}
}

// wsDialRaw performs a raw handshake and returns the open connection with
// its buffered reader, so the test controls wire fragmentation exactly.
func wsDialRaw(t *testing.T, h *harness, cookie, wsPath, offer string) (net.Conn, *bufio.Reader) {
	t.Helper()
	addr := h.relaySrv.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(bytes_Repeat("k", 16))
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\nHost: %s:%s\r\n", wsPath, h.host(), testPort(h))
	fmt.Fprintf(&sb, "Upgrade: websocket\r\nConnection: Upgrade\r\n")
	fmt.Fprintf(&sb, "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", key)
	fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
	fmt.Fprintf(&sb, "Origin: http://%s:%s\r\n", h.host(), testPort(h))
	if offer != "" {
		fmt.Fprintf(&sb, "Sec-WebSocket-Protocol: %s\r\n", offer)
	}
	sb.WriteString("\r\n")
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		conn.Close()
		t.Fatalf("raw ws handshake: status=%q err=%v", strings.TrimSpace(status), err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	return conn, br
}

// wsWriteRawFrame writes one client-masked frame with explicit FIN/opcode.
func wsWriteRawFrame(t *testing.T, conn net.Conn, fin bool, opcode byte, payload []byte) {
	t.Helper()
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	hdr := []byte{b0}
	n := len(payload)
	const maskBit = 0x80
	switch {
	case n < 126:
		hdr = append(hdr, maskBit|byte(n))
	case n < 65536:
		hdr = append(hdr, maskBit|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, maskBit|127, 0, 0, 0, 0,
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		t.Fatal(err)
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := conn.Write(append(hdr, masked...)); err != nil {
		t.Fatal(err)
	}
}

// wsReadRawMessage reassembles one server message across continuation frames.
func wsReadRawMessage(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	var firstOp byte
	var msg []byte
	for {
		h, err := br.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		b1, err := br.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		fin := h&0x80 != 0
		op := h & 0x0f
		if op == 0x8 {
			t.Fatal("server closed during fragmented echo")
		}
		n := int(b1 & 0x7f)
		switch n {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				t.Fatal(err)
			}
			n = int(ext[0])<<8 | int(ext[1])
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				t.Fatal(err)
			}
			n = 0
			for _, b := range ext {
				n = n<<8 | int(b)
			}
		}
		// Server-to-client frames are unmasked. Control frames (ping/pong)
		// carry no message bytes: skip them without disturbing reassembly.
		chunk := make([]byte, n)
		if _, err := io.ReadFull(br, chunk); err != nil {
			t.Fatal(err)
		}
		if op == 0x9 || op == 0xA {
			continue
		}
		if op != 0x0 {
			firstOp = op
		}
		msg = append(msg, chunk...)
		if fin {
			return firstOp, msg
		}
	}
}

// TestWebSocketFragmentedMessage: a message split across continuation
// frames must survive the tunnel and echo back intact (P1-10).
func TestWebSocketFragmentedMessage(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	conn, br := wsDialRaw(t, h, cookie, "/ws", "")
	defer conn.Close()
	wsWriteRawFrame(t, conn, false, 0x1, []byte("frag-"))
	wsWriteRawFrame(t, conn, true, 0x0, []byte("mented"))
	op, got := wsReadRawMessage(t, br)
	if op != 0x1 || string(got) != "frag-mented" {
		t.Fatalf("fragmented echo: op=%x body=%q", op, got)
	}
	// A fragmented binary message interleaved with a ping still reassembles.
	// Control frames must never be fragmented (RFC 6455): FIN is set.
	wsWriteRawFrame(t, conn, false, 0x2, bytes_Repeat("A", 1000))
	wsWriteRawFrame(t, conn, true, 0x9, []byte("ping"))
	wsWriteRawFrame(t, conn, true, 0x0, bytes_Repeat("B", 1000))
	op, got = wsReadRawMessage(t, br)
	if op != 0x2 || len(got) != 2000 {
		t.Fatalf("fragmented binary echo: op=%x len=%d", op, len(got))
	}
}

// TestWebSocketAbruptCloseNoPoison: a visitor that vanishes mid-stream
// (no close handshake) must not wedge the lease: a fresh WS dial and plain
// HTTP both keep working afterward (P1-10).
func TestWebSocketAbruptCloseNoPoison(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	conn, _ := wsDialRaw(t, h, cookie, "/ws", "")
	wsWriteRawFrame(t, conn, false, 0x2, bytes_Repeat("C", 4096))
	// Vanish without a close frame; the tunnel must notice and recover.
	_ = conn.Close()
	deadline := time.Now().Add(20 * time.Second)
	for {
		probe, _ := wsDialRaw(t, h, cookie, "/ws", "")
		wsWriteRawFrame(t, probe, true, 0x1, []byte("alive?"))
		_ = probe.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, got, rerr := wsReadRawMessageOnce(probe)
		probe.Close()
		if rerr == nil && string(got) == "alive?" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel wedged after abrupt close: last err=%v", rerr)
		}
		time.Sleep(200 * time.Millisecond)
	}
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("http after abrupt ws close: status %d", resp.StatusCode)
	}
}

// wsReadRawMessageOnce reads a single server frame (no reassembly).
func wsReadRawMessageOnce(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	op := hdr[0] & 0x0f
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(conn, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int(ext[0])<<8 | int(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(conn, ext[:]); err != nil {
			return 0, nil, err
		}
		n = 0
		for _, b := range ext {
			n = n<<8 | int(b)
		}
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return 0, nil, err
	}
	return op, msg, nil
}

// TestWebSocketHighThroughput: concurrent connections with interleaved
// messages in both directions all echo intact while HTTP stays responsive
// (P1-10: bidirectional high-throughput, no cross-stream corruption).
func TestWebSocketHighThroughput(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	const conns = 8
	const msgs = 20
	var wg sync.WaitGroup
	errs := make(chan string, conns*msgs)
	for c := 0; c < conns; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			conn := wsDial(t, h, cookie)
			defer conn.Close(websocket.StatusNormalClosure, "")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			for i := 0; i < msgs; i++ {
				want := fmt.Sprintf("tput-%d-%d-%s", c, i, strings.Repeat("x", 4000))
				if err := conn.Write(ctx, websocket.MessageText, []byte(want)); err != nil {
					errs <- fmt.Sprintf("conn %d write %d: %v", c, i, err)
					return
				}
				_, got, err := conn.Read(ctx)
				if err != nil {
					errs <- fmt.Sprintf("conn %d read %d: %v", c, i, err)
					return
				}
				if string(got) != want {
					errs <- fmt.Sprintf("conn %d msg %d mismatch: %d bytes", c, i, len(got))
					return
				}
			}
		}(c)
	}
	// HTTP must stay responsive under WS load.
	httpOK := true
	for i := 0; i < 10; i++ {
		resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
		body := readAll(t, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || body != "hello" {
			httpOK = false
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if !httpOK {
		t.Fatal("http unresponsive during ws throughput")
	}
}

func bytes_Repeat(s string, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = s[0]
	}
	return b
}
