package relay

// Relay-side WebSocket hijack coverage (round 7).
//
// A client may pipeline WebSocket frames immediately after its upgrade
// GET; the HTTP server buffers those bytes past the handshake and hands
// them to us only via the hijacked bufrw. Reading the raw conn would
// lose them, corrupting the stream start. The agent side already
// preserves its own handshake buffer (agent_ws.go); this pins the relay
// side to the same contract.

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"ocliv/internal/protocol"
)

func TestDrainHijackedBytesForwardsBuffered(t *testing.T) {
	var backing bytes.Buffer
	backing.WriteString("GET /chat HTTP/1.1\r\nPIPELINED-FRAME-BYTES")
	rw := bufio.NewReadWriter(bufio.NewReader(&backing), bufio.NewWriter(io.Discard))
	// Simulate the server consuming exactly the handshake: the read
	// pulls available bytes into bufio's internal buffer, leaving the
	// pipelined frame bytes buffered but unconsumed — the state Hijack
	// hands us in production.
	if line, err := rw.Reader.ReadString('\n'); err != nil || line != "GET /chat HTTP/1.1\r\n" {
		t.Fatalf("handshake read = %q, %v", line, err)
	}
	var got []byte
	calls := 0
	if err := drainHijackedBytes(rw, func(p []byte) error {
		calls++
		got = append(got, p...)
		return nil
	}); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if string(got) != "PIPELINED-FRAME-BYTES" {
		t.Fatalf("forwarded %q, want pipelined bytes intact and ordered", got)
	}
	if err := drainHijackedBytes(rw, func(p []byte) error {
		calls++
		return nil
	}); err != nil {
		t.Fatalf("drain empty: %v", err)
	}
	if calls != 1 {
		t.Fatalf("empty buffer forwarded: calls=%d, want 1", calls)
	}
}

type failHijackRecorder struct {
	hijackRecorder
}

func (f *failHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("hijack unsupported here")
}

// A failed Hijack must produce an explicit 500, not a silent return
// that leaves the visitor hanging.
func TestWSHijackFailureReports500(t *testing.T) {
	s, _ := newLifecycleServer(t)
	relayEnd, agentEnd := net.Pipe()
	defer relayEnd.Close()
	defer agentEnd.Close()
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	// A real agent always reads its stream end; without a drainer the
	// relay's abort write would block on the synchronous pipe.
	go func() {
		_, _ = io.Copy(io.Discard, agentEnd)
	}()
	raw, err := protocol.MarshalJSON(
		protocol.UpgradeAccept{Type: "upgrade_accept", Accept: wsAccept(key)})
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	if err := protocol.WriteFrame(&frame, protocol.FUpgradeAccept, raw); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = agentEnd.Write(frame.Bytes())
	}()
	req := httptest.NewRequest(http.MethodGet, "http://visitor.test/", nil)
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	w := &failHijackRecorder{hijackRecorder: hijackRecorder{header: http.Header{}}}
	s.serveWebSocket(w, req, relayEnd, "req-test", &routeTarget{}, nil)
	if w.status != http.StatusInternalServerError {
		t.Fatalf("hijack failure status=%d, want 500", w.status)
	}
}
