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
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/B-A-M-N/ocliv/internal/limits"
	"github.com/B-A-M-N/ocliv/internal/protocol"
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

// A real subscriptions/listen request is application-idle while its yamux
// transport remains healthy. Transport keepalives, not response-frame
// deadlines, own dead-peer detection. The default test stays fast; set
// OCLIV_LONG_STREAM_TESTS=1 for the separate 45/90/180-second endurance run.
func TestQuietMCPSubscriptionGaps(t *testing.T) {
	for _, gap := range []time.Duration{20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond} {
		t.Run(gap.String(), func(t *testing.T) { runQuietMCPSubscriptionGap(t, gap) })
	}
}

func TestQuietMCPSubscriptionEndurance(t *testing.T) {
	if os.Getenv("OCLIV_LONG_STREAM_TESTS") != "1" {
		t.Skip("set OCLIV_LONG_STREAM_TESTS=1 to run 45/90/180-second stream endurance")
	}
	for _, gap := range []time.Duration{45 * time.Second, 90 * time.Second, 180 * time.Second} {
		t.Run(gap.String(), func(t *testing.T) { runQuietMCPSubscriptionGap(t, gap) })
	}
}

func runQuietMCPSubscriptionGap(t *testing.T, gap time.Duration) {
	t.Helper()
	s, _ := newLifecycleServer(t)
	relayEnd, agentEnd := net.Pipe()
	defer relayEnd.Close()
	defer agentEnd.Close()
	w := newHijackRecorder(t)
	defer w.testEnd.Close()
	subscription := `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"uri":"test://quiet"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(subscription))
	x := newHTTPExchange(s, w, req, relayEnd, &routeTarget{LeaseID: "quiet-subscription", ExpiresAt: time.Now().Add(10 * time.Minute)})
	done := make(chan struct{})
	go func() {
		defer close(done)
		x.run()
	}()
	var uploaded []byte
	for {
		ft, payload, err := protocol.ReadFrame(agentEnd)
		if err != nil {
			t.Fatalf("read subscription request: %v", err)
		}
		switch ft {
		case protocol.FRequestData:
			uploaded = append(uploaded, payload...)
		case protocol.FRequestEnd:
			if !strings.Contains(string(uploaded), `"method":"subscriptions/listen"`) {
				t.Fatalf("request was not subscriptions/listen: %s", uploaded)
			}
			goto requestSent
		default:
			t.Fatalf("unexpected request frame %d", ft)
		}
	}
requestSent:
	writeResponseFrameBounded(t, agentEnd, relayEnd, protocol.FResponseHead, protocol.ResponseHead{
		Type: "response_head", Proto: protocol.Version, RequestID: "quiet-subscription", Status: http.StatusOK,
		Headers: map[string]string{"Content-Type": "text/event-stream"},
	})
	time.Sleep(gap)
	payload := []byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{}}\n\n")
	writeProtocolFrameBounded(t, agentEnd, relayEnd, protocol.FResponseData, payload)
	writeResponseFrameBounded(t, agentEnd, relayEnd, protocol.FResponseEnd, protocol.EndFrame{Type: "response_end"})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("subscription did not finish after event")
	}
	w.mu.Lock()
	got := w.body.String()
	w.mu.Unlock()
	if got != string(payload) {
		t.Fatalf("response after %s quiet gap = %q, want event", gap, got)
	}
}

func writeResponseFrameBounded(t *testing.T, w, peer net.Conn, ftype byte, v any) {
	t.Helper()
	raw, err := protocol.MarshalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	writeProtocolFrameBounded(t, w, peer, ftype, raw)
}

func writeProtocolFrameBounded(t *testing.T, w, peer net.Conn, ftype byte, raw []byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- protocol.WriteFrame(w, ftype, raw) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write response frame: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = w.Close()
		_ = peer.Close()
		t.Fatal("response frame write blocked; closed both net.Pipe ends")
	}
}

func TestRenewedLeaseKeepsQuietStreamUntilRevocation(t *testing.T) {
	s, db := newLifecycleServer(t)
	insertLeaseRow(t, db, "stream-renew", "ACTIVE", 7, nil)
	initialExpiry := time.Now().UTC().Add(100 * time.Millisecond)
	if _, err := db.SQL().Exec(`UPDATE leases SET expires_at=? WHERE id='stream-renew'`, initialExpiry.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	relayConn, agentConn := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Millisecond
	cfg.ConnectionWriteTimeout = 100 * time.Millisecond
	relaySession, err := yamux.Server(relayConn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	agentSession, err := yamux.Client(agentConn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relaySession.Close(); _ = agentSession.Close() })
	stream, err := relaySession.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	agentStream, err := agentSession.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	s.registry.mu.Lock()
	s.registry.sessions["stream-renew"] = &Session{LeaseID: "stream-renew", Generation: 7, Yamux: relaySession, closed: make(chan struct{})}
	s.registry.mu.Unlock()
	w := newHijackRecorder(t)
	defer w.testEnd.Close()
	x := &httpExchange{srv: s, w: w, stream: stream, ctx: context.Background(),
		t:          &routeTarget{LeaseID: "stream-renew", Generation: 7, ExpiresAt: initialExpiry},
		headStatus: http.StatusOK, uploadClean: true}
	done := make(chan struct{})
	go func() { defer close(done); x.streamBody() }()
	newExpiry := time.Now().UTC().Add(450 * time.Millisecond)
	if _, err := db.SQL().Exec(`UPDATE leases SET expires_at=? WHERE id='stream-renew'`, newExpiry.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // pass the original snapshot expiry
	event := []byte("event: message\ndata: renewal survived\n\n")
	writeProtocolFrameBounded(t, agentStream, stream, protocol.FResponseData, event)
	deadline := time.Now().Add(time.Second)
	for {
		w.mu.Lock()
		got := w.body.String()
		w.mu.Unlock()
		if got == string(event) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("renewed subscription did not deliver event; body=%q", got)
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.revokeLease("stream-renew"); err != nil {
		t.Fatal(err)
	}
	s.evictLease("stream-renew") // same post-commit action used by explicit revoke
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("explicit revoke did not close the active stream")
	}
}

func TestQuietStreamInterruptsOnDisconnectAndLeaseExpiry(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, func())
		exp  time.Time
	}{
		{name: "visitor disconnect", ctx: func() (context.Context, func()) { return context.WithCancel(context.Background()) }, exp: time.Now().Add(time.Hour)},
		{name: "lease expiry", ctx: func() (context.Context, func()) { return context.Background(), func() {} }, exp: time.Now().Add(20 * time.Millisecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newLifecycleServer(t)
			relayEnd, agentEnd := net.Pipe()
			defer relayEnd.Close()
			defer agentEnd.Close()
			w := newHijackRecorder(t)
			defer w.testEnd.Close()
			ctx, cancel := tc.ctx()
			defer cancel()
			x := &httpExchange{srv: s, w: w, stream: relayEnd, ctx: ctx, t: &routeTarget{LeaseID: "quiet-cancel", ExpiresAt: tc.exp}, headStatus: http.StatusOK, uploadClean: true}
			done := make(chan struct{})
			go func() { defer close(done); x.streamBody() }()
			if tc.name == "visitor disconnect" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("quiet stream did not stop after cancellation condition")
			}
		})
	}
}

func TestYamuxKeepaliveStaysBelowMCPStreamAndDetectsDisconnect(t *testing.T) {
	newPair := func(t *testing.T) (*yamux.Session, *yamux.Session, net.Conn, net.Conn) {
		t.Helper()
		relayConn, agentConn := net.Pipe()
		cfg := yamux.DefaultConfig()
		cfg.KeepAliveInterval = 20 * time.Millisecond
		cfg.ConnectionWriteTimeout = 100 * time.Millisecond
		relaySession, err := yamux.Client(relayConn, cfg)
		if err != nil {
			t.Fatal(err)
		}
		agentSession, err := yamux.Server(agentConn, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return relaySession, agentSession, relayConn, agentConn
	}

	t.Run("transport pings are not response frames", func(t *testing.T) {
		relaySession, agentSession, relayConn, agentConn := newPair(t)
		defer relayConn.Close()
		defer agentConn.Close()
		defer relaySession.Close()
		defer agentSession.Close()
		relayStream, err := relaySession.Open()
		if err != nil {
			t.Fatal(err)
		}
		agentStream, err := agentSession.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer relayStream.Close()
		defer agentStream.Close()

		s, _ := newLifecycleServer(t)
		w := newHijackRecorder(t)
		defer w.testEnd.Close()
		x := &httpExchange{srv: s, w: w, stream: relayStream, ctx: context.Background(),
			t: &routeTarget{LeaseID: "yamux-quiet", ExpiresAt: time.Now().Add(time.Hour)}, headStatus: http.StatusOK, uploadClean: true}
		done := make(chan struct{})
		go func() { defer close(done); x.streamBody() }()
		time.Sleep(100 * time.Millisecond) // several transport pings, no application data
		if err := protocol.WriteFrame(agentStream, protocol.FResponseData, []byte("event")); err != nil {
			t.Fatal(err)
		}
		writeResponseFrame(t, agentStream, protocol.FResponseEnd, protocol.EndFrame{Type: "response_end"})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("quiet stream did not finish after application data")
		}
		w.mu.Lock()
		got := w.body.String()
		w.mu.Unlock()
		if got != "event" {
			t.Fatalf("application body=%q, want only the MCP event", got)
		}
	})

	t.Run("peer loss releases quiet stream", func(t *testing.T) {
		relaySession, agentSession, relayConn, agentConn := newPair(t)
		defer relayConn.Close()
		defer agentConn.Close()
		defer relaySession.Close()
		defer agentSession.Close()
		relayStream, err := relaySession.Open()
		if err != nil {
			t.Fatal(err)
		}
		agentStream, err := agentSession.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer relayStream.Close()
		defer agentStream.Close()

		s, _ := newLifecycleServer(t)
		w := newHijackRecorder(t)
		defer w.testEnd.Close()
		x := &httpExchange{srv: s, w: w, stream: relayStream, ctx: context.Background(),
			t: &routeTarget{LeaseID: "yamux-disconnect", ExpiresAt: time.Now().Add(time.Hour)}, headStatus: http.StatusOK, uploadClean: true}
		done := make(chan struct{})
		go func() { defer close(done); x.streamBody() }()
		if err := agentConn.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("peer disconnect did not release quiet stream")
		}
	})
}
