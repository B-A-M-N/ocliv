package relay

// Deterministic terminal-frame hold test (Finding 5 / F1).
//
// An integration test cannot force this interleaving through the current
// all-Go stack: Go's client Transport does not surface a response head
// while its own request body is still streaming, and the agent uses that
// same Transport — so a fully early upstream response racing a slow
// visitor upload never materializes end to end (verified with isolated
// stdlib probes). The relay is transport-agnostic and must still be
// correct when the interleave DOES occur (non-Go agents, proxies, future
// agent changes), so this test pins the invariant at the layer that owns
// it, with a fake stream: feed a complete success response while the
// visitor body is still trickling, then abort the upload. The delivery
// must tear down (connection close), never end cleanly.

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ocliv/internal/limits"
	"ocliv/internal/protocol"
)

// hijackRecorder is an http.ResponseWriter whose connection the test can
// observe: teardown closes the relay end, which surfaces as EOF on the
// test end. A clean completion leaves the connection open.
type hijackRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	mu     sync.Mutex

	relayEnd net.Conn
	testEnd  net.Conn
}

func newHijackRecorder(t *testing.T) *hijackRecorder {
	t.Helper()
	a, b := net.Pipe()
	return &hijackRecorder{header: http.Header{}, relayEnd: a, testEnd: b}
}

func (h *hijackRecorder) Header() http.Header { return h.header }

func (h *hijackRecorder) WriteHeader(status int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status = status
}

func (h *hijackRecorder) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.body.Write(p)
}

func (h *hijackRecorder) Flush() {}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.relayEnd, nil, nil
}

func writeResponseFrame(t *testing.T, w io.Writer, ftype byte, v any) {
	t.Helper()
	raw, err := protocol.MarshalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(w, ftype, raw); err != nil {
		t.Fatal(err)
	}
}

// TestHeldEndOnLateUploadFailure: a full 200 response delivered while the
// visitor upload is still in flight must not complete cleanly when the
// upload then aborts. Data already streamed stays delivered; the terminal
// frame is held for the upload outcome, and the abort turns it into a
// teardown (observed as EOF on the connection, not a clean chunked end).
func TestHeldEndOnLateUploadFailure(t *testing.T) {
	s, _ := newLifecycleServer(t)

	relayEnd, agentEnd := net.Pipe()
	defer relayEnd.Close()
	defer agentEnd.Close()

	// Slow visitor body: trickles until the test aborts it.
	bodyR, bodyW := io.Pipe()
	abort := errors.New("visitor aborted upload")
	go func() {
		defer bodyW.Close()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for i := 0; i < 200; i++ {
			select {
			case <-tick.C:
				if _, err := bodyW.Write([]byte("u")); err != nil {
					return
				}
			}
		}
	}()

	req := httptest.NewRequest(http.MethodPost, "/", bodyR)
	w := newHijackRecorder(t)
	defer w.testEnd.Close()
	xchg := newHTTPExchange(s, w, req, relayEnd, &routeTarget{LeaseID: "hold-test"})
	done := make(chan struct{})
	go func() {
		defer close(done)
		xchg.run()
	}()

	// Drain the agent side the way a live agent would: consume request
	// frames as they arrive. Without this the relay's upload worker
	// blocks on its first DATA write and the test would wedge instead
	// of racing the response against the upload.
	var agentSawEnd atomic.Bool
	go func() {
		for {
			ft, _, err := protocol.ReadFrame(agentEnd)
			if err != nil {
				return
			}
			if ft == protocol.FRequestEnd {
				agentSawEnd.Store(true)
				return
			}
		}
	}()

	// The whole upstream response arrives while the upload runs. Head
	// and end frames carry JSON structs; data frames carry raw body
	// bytes exactly as the agent writes them.
	writeResponseFrame(t, agentEnd, protocol.FResponseHead, protocol.ResponseHead{
		Type: "response_head", Proto: protocol.Version, RequestID: "r1",
		Status: 200, Headers: map[string]string{},
	})
	if err := protocol.WriteFrame(agentEnd, protocol.FResponseData, []byte("early-ok")); err != nil {
		t.Fatal(err)
	}
	writeResponseFrame(t, agentEnd, protocol.FResponseEnd, protocol.EndFrame{Type: "response_end"})

	// Data streams incrementally even while the end is held.
	deadline := time.Now().Add(10 * time.Second)
	for {
		w.mu.Lock()
		got := w.body.String()
		w.mu.Unlock()
		if got == "early-ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("response data never streamed, got %q", got)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The upload is still in flight (200 bytes at 50ms), so a correct
	// exchange must still be open: the terminal frame is held for the
	// upload outcome. If the exchange already finished, the end was
	// delivered without the outcome — the false success.
	select {
	case <-done:
		t.Fatal("terminal frame delivered while the upload was still in flight")
	case <-time.After(time.Second):
	}

	// Abort the stalled upload; the held end must become a teardown,
	// and the aborted body must never complete upstream.
	_ = bodyW.CloseWithError(abort)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("exchange never finished after upload abort")
	}
	if agentSawEnd.Load() {
		t.Fatal("aborted upload was completed upstream with REQUEST_END")
	}
	// Teardown actively closes the connection, which surfaces as prompt
	// EOF. A clean completion would leave the connection open (nothing
	// closes it on the clean path), so a read would block until the
	// deadline instead. Prompt EOF therefore proves teardown, not a
	// clean chunked end.
	w.testEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	rest, err := io.ReadAll(w.testEnd)
	if os.IsTimeout(err) {
		t.Fatalf("connection left open after abort: end completed cleanly (%d bytes)", len(rest))
	}
	if err != nil {
		t.Fatalf("unexpected read error after teardown: %v", err)
	}
}

// TestStalledUploadWithEarlySuccessTearsDown (P1-9): when the full 200
// response arrives early and the upload then STALLS (no progress for a
// full idle window, client still attached), the exchange must tear down,
// never report clean completion. An incomplete request cannot be a
// complete delivery; early success responses stream incrementally, but
// the terminal frame requires a completed upload.
func TestStalledUploadWithEarlySuccessTearsDown(t *testing.T) {
	oldFirstByte := limits.FirstByteTimeout
	limits.FirstByteTimeout = 2 * time.Second
	defer func() { limits.FirstByteTimeout = oldFirstByte }()

	s, _ := newLifecycleServer(t)

	relayEnd, agentEnd := net.Pipe()
	defer relayEnd.Close()
	defer agentEnd.Close()

	// Visitor body trickles briefly, then stalls with the pipe open.
	bodyR, bodyW := io.Pipe()
	stalled := errors.New("stalled client went away")
	go func() {
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for i := 0; i < 10; i++ {
			select {
			case <-tick.C:
				if _, err := bodyW.Write([]byte("u")); err != nil {
					return
				}
			}
		}
		// Stop writing; keep the pipe open to simulate a stall
		// (not an abort, not a completion).
		<-time.After(30 * time.Second)
	}()

	req := httptest.NewRequest(http.MethodPost, "/", bodyR)
	w := newHijackRecorder(t)
	defer w.testEnd.Close()
	xchg := newHTTPExchange(s, w, req, relayEnd, &routeTarget{LeaseID: "hold-test-stall"})
	done := make(chan struct{})
	go func() {
		defer close(done)
		xchg.run()
	}()

	// Drain the agent side the way a live agent would.
	var agentSawEnd atomic.Bool
	go func() {
		for {
			ft, _, err := protocol.ReadFrame(agentEnd)
			if err != nil {
				return
			}
			if ft == protocol.FRequestEnd {
				agentSawEnd.Store(true)
				return
			}
		}
	}()

	// Full upstream success arrives while the upload runs.
	writeResponseFrame(t, agentEnd, protocol.FResponseHead, protocol.ResponseHead{
		Type: "response_head", Proto: protocol.Version, RequestID: "r1",
		Status: 200, Headers: map[string]string{},
	})
	if err := protocol.WriteFrame(agentEnd, protocol.FResponseData, []byte("early-ok")); err != nil {
		t.Fatal(err)
	}
	writeResponseFrame(t, agentEnd, protocol.FResponseEnd, protocol.EndFrame{Type: "response_end"})

	// Data streams incrementally even while the end is held.
	deadline := time.Now().Add(10 * time.Second)
	for {
		w.mu.Lock()
		got := w.body.String()
		w.mu.Unlock()
		if got == "early-ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("response data never streamed, got %q", got)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The trickle stopped; the idle window (2s) must end the wait with a
	// teardown, not a clean completion. Teardown closes the connection
	// (prompt EOF); clean completion would leave it open (read timeout).
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("exchange never finished after upload stalled")
	}
	if agentSawEnd.Load() {
		t.Fatal("stalled upload was completed upstream with REQUEST_END")
	}
	w.testEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	rest, err := io.ReadAll(w.testEnd)
	if os.IsTimeout(err) {
		t.Fatalf("stalled upload finalized cleanly (%d bytes); want teardown", len(rest))
	}
	if err != nil {
		t.Fatalf("unexpected read error after teardown: %v", err)
	}
	_ = bodyW.CloseWithError(stalled)
}
