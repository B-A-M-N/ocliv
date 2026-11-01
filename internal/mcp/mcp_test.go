package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// startEcho returns an adapter whose child echoes stdin to stdout (cat).
// The request body is the untrusted remote input; the adapter must treat
// it opaquely.
func startEcho(t *testing.T, mutate func(*Options)) *Adapter {
	t.Helper()
	o := Options{Command: "cat", Timeout: 5 * time.Second}
	if mutate != nil {
		mutate(&o)
	}
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return a
}

// startSilent returns an adapter whose child never emits stdout (sleep):
// it models a real MCP server's behavior for notifications, which
// require no reply. Any read for a reply line blocks until timeout.
func startSilent(t *testing.T, timeout time.Duration) *Adapter {
	t.Helper()
	a, err := New(Options{Command: "sleep", Args: []string{"30"}, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestNotificationNeedsNoReply: a JSON-RPC notification (no id) is a
// write-only child operation returning 202. Waiting for a reply line
// stalls 30s and retires a healthy adapter.
func TestNotificationNeedsNoReply(t *testing.T) {
	a := startSilent(t, 5*time.Second)
	start := time.Now()
	req := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	if dt := time.Since(start); dt > 2*time.Second {
		t.Fatalf("notification blocked %v waiting for a reply that never comes", dt)
	}
	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%q, want 202", w.Code, w.Body.String())
	}
	if a.broken.Load() {
		t.Fatal("healthy adapter retired after a notification")
	}
}

// TestMalformedBodyRejectedBeforeChild: non-JSON-RPC input is a 400 and
// never reaches the child's stdin.
func TestMalformedBodyRejectedBeforeChild(t *testing.T) {
	a := startSilent(t, 5*time.Second)
	start := time.Now()
	w := post(t, a, `this is not json-rpc`)
	if dt := time.Since(start); dt > 2*time.Second {
		t.Fatalf("malformed body blocked %v against a silent child", dt)
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q, want 400", w.Code, w.Body.String())
	}
}

func post(t *testing.T, a *Adapter, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

// TestAdapterEchoRoundTrip: the happy path pins that one POST becomes one
// stdio message and the single reply line comes back byte-for-byte.
func TestAdapterEchoRoundTrip(t *testing.T) {
	a := startEcho(t, nil)
	w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n" {
		t.Fatalf("reply mismatch: %q", got)
	}
	if n := a.Spawned(); n != 1 {
		t.Fatalf("spawned=%d, want exactly 1", n)
	}
}

// TestNoShellInterpretation (M07): shell metacharacters in the command or
// the request body are literal data, never interpreted. The body attempts
// classic command substitution; cat echoes it back and no file may appear.
func TestNoShellInterpretation(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "pwned")
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"$(touch %s)"}`, probe)
	a := startEcho(t, nil)
	w := post(t, a, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "$(touch") {
		t.Fatalf("body was interpreted instead of echoed: %q", w.Body.String())
	}
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Fatalf("injected command executed: %s exists", probe)
	}
	if n := a.Spawned(); n != 1 {
		t.Fatalf("HTTP traffic spawned processes: spawned=%d", n)
	}
}

// TestCommandWithSpacesRejected (M07): a command naming an executable plus
// arguments as one string is a literal path lookup and must fail —
// arguments travel only via argv, never via shell parsing.
func TestCommandWithSpacesRejected(t *testing.T) {
	if _, err := New(Options{Command: "echo pwned"}); err == nil {
		t.Fatal("space-containing command resolved; shell splitting suspected")
	}
	if _, err := New(Options{Command: ""}); err == nil {
		t.Fatal("empty command accepted")
	}
	if _, err := New(Options{Command: "definitely-not-a-real-binary-xyz"}); err == nil {
		t.Fatal("nonexistent command accepted")
	}
}

// TestEnvScrubbed (M08): the child never inherits ambient operator
// credentials; only PATH plus explicit entries are present. printenv
// probes one variable per round trip (the adapter speaks single-line
// messages), so a positive control and a negative control run separately.
func TestEnvScrubbed(t *testing.T) {
	const sentinelKey = "OCLIV_MCP_TEST_SENTINEL"
	const sentinelVal = "top-secret-operator-value-12345"
	t.Setenv(sentinelKey, sentinelVal)
	// Positive control: an explicit entry reaches the child.
	pos := startEcho(t, func(o *Options) {
		o.Command = "sh"
		o.Args = []string{"-c", `IFS= read -r req; echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"$MCP_ROLE\"}"`}
		o.Env = []string{"MCP_ROLE=test"}
	})
	// Positive control: an explicit entry reaches the child. The fixture
	// is a canned JSON-RPC reply carrying the variable, so the adapter's
	// id correlation accepts it as the call's answer.
	w := post(t, pos, `{"jsonrpc":"2.0","id":1,"method":"probe"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"result":"test"`) {
		t.Fatalf("explicit env entry missing: status=%d body=%q", w.Code, w.Body.String())
	}
	// Negative control: an ambient operator credential is absent. The
	// reply carries the empty expansion; a 200 containing the value
	// would prove a leak.
	neg := startEcho(t, func(o *Options) {
		o.Command = "sh"
		o.Args = []string{"-c", `IFS= read -r req; echo "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"$` + sentinelKey + `\"}"`}
	})
	w2 := post(t, neg, `{"jsonrpc":"2.0","id":2,"method":"probe"}`)
	if strings.Contains(w2.Body.String(), sentinelVal) {
		t.Fatalf("ambient credential leaked to child: %q", w2.Body.String())
	}
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), `"result":""`) {
		t.Fatalf("sentinel probe status=%d body=%q, want 200 with empty result", w2.Code, w2.Body.String())
	}
}

// TestWorkingDirPinned (M07/M08): the child runs in the operator-chosen
// directory; requests cannot change it.
func TestWorkingDirPinned(t *testing.T) {
	dir := t.TempDir()
	a := startEcho(t, func(o *Options) {
		o.Command = "sh"
		o.Args = []string{"-c", `IFS= read -r req; echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"$PWD\"}"`}
		o.Dir = dir
	})
	w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"probe","params":{"dir":"/tmp/evil"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if got := w.Body.String(); !strings.Contains(got, `"result":`+strconv.Quote(dir)) {
		t.Fatalf("child dir reply=%q want %q", got, dir)
	}
}

// TestLoopbackOnly (M08): the listener binds 127.0.0.1, never 0.0.0.0.
func TestLoopbackOnly(t *testing.T) {
	a := startEcho(t, nil)
	addr := a.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("adapter bound %q, want 127.0.0.1:*", addr)
	}
}

// TestOversizeRequestRejected (M13): an over-limit body is rejected before
// touching the child.
func TestOversizeRequestRejected(t *testing.T) {
	a := startEcho(t, func(o *Options) { o.MaxBodyBytes = 16 })
	w := post(t, a, strings.Repeat("x", 1024))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413", w.Code)
	}
}

// waitPending blocks until the coordinator has registered the waiter
// for id (or fails). It removes scheduling luck from tests that must
// deliver child output while a request is in flight: the write happens
// strictly after registration, so the reply path is the only outcome.
func waitPending(t *testing.T, a *Adapter, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		a.coord.mu.Lock()
		_, ok := a.coord.pending[id]
		a.coord.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiter %q never registered", id)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestOversizeChildOutputRejected (M13): untrusted child output past the
// cap is rejected, never forwarded as a truncated reply, and the adapter
// retires fail-closed.
//
// Determinism note: `cat file` emits eagerly at startup, so whether the
// oversize line lands before or after the request's waiter registers is a
// race (502 with waiter pending, 503 once retired). To pin the reply path
// deterministically, the child is `cat fifo`: it blocks opening the fifo
// until the test writes, so the 1KiB line can only arrive while the
// request is in flight.
func TestOversizeChildOutputRejected(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "long.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	a := startEcho(t, func(o *Options) {
		o.Command = "cat"
		o.Args = []string{fifo}
		o.MaxBodyBytes = 64
	})
	type result struct{ code int }
	got := make(chan result, 1)
	go func() {
		w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"p"}`)
		got <- result{w.Code}
	}()
	// The child is still blocked opening the fifo; the reply path is
	// the only possible outcome once the waiter below is registered.
	waitPending(t, a, "1")
	f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(strings.Repeat("x", 1024) + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	select {
	case r := <-got:
		if r.code != http.StatusBadGateway {
			t.Fatalf("status=%d want 502 for oversize child output", r.code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("oversize reply never answered")
	}
	// The adapter retired on the violation: later requests fail closed.
	w := post(t, a, `{"jsonrpc":"2.0","id":2,"method":"p"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 after oversize retirement", w.Code)
	}
}

// TestUnterminatedChildOutputRejected: EOF without a newline is a
// malformed reply, never a clean completion.
//
// Determinism note (same eager-output race as the oversize test): a child
// that prints at startup can retire the adapter before the request's
// waiter registers (503) instead of answering it (502). `cat fifo` blocks
// until the test writes, so the unterminated tail can only arrive while
// the waiter is pending; closing the fifo without a newline then ends
// the stream mid-line.
func TestUnterminatedChildOutputRejected(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "tail.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	a := startEcho(t, func(o *Options) {
		o.Command = "cat"
		o.Args = []string{fifo}
	})
	type result struct{ code int }
	got := make(chan result, 1)
	go func() {
		w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"probe"}`)
		got <- result{w.Code}
	}()
	// The child is still blocked opening the fifo; write only after the
	// waiter is registered.
	waitPending(t, a, "1")
	f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("no-newline-here"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	select {
	case r := <-got:
		if r.code != http.StatusBadGateway {
			t.Fatalf("status=%d want 502 for unterminated child output", r.code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("unterminated reply never answered")
	}
}

// TestConcurrencyExhaustion (M13): beyond MaxConcurrent, callers get 503
// while the in-flight exchange is still pending. sleep never replies, so
// the first waiter is released by cancelling the child; the point under
// test is that the second caller is rejected promptly, not queued.
func TestConcurrencyExhaustion(t *testing.T) {
	a, err := New(Options{
		Command:       "sleep",
		Args:          []string{"30"},
		MaxConcurrent: 1,
		Timeout:       30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() { _ = a.Close() }()
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	firstDone := make(chan int, 1)
	go func() {
		defer wg.Done()
		firstDone <- post(t, a, `{"jsonrpc":"2.0","id":1,"method":"slow"}`).Code
	}()
	waitPending(t, a, "1") // first request holds the slot; no sleep-based luck
	second := post(t, a, `{"jsonrpc":"2.0","id":2,"method":"slow"}`)
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status=%d want 503", second.Code)
	}
	cancel() // release the pending waiter by killing the child
	select {
	case <-firstDone:
	case <-time.After(10 * time.Second):
		t.Fatal("pending exchange never released after cancel")
	}
	wg.Wait()
}

// TestTimeoutRetiresAdapter (M13): a wedged child fails closed — the
// waiter gets 504 and the adapter refuses further work with 503.
func TestTimeoutRetiresAdapter(t *testing.T) {
	a := startEcho(t, func(o *Options) {
		o.Command = "sleep"
		o.Args = []string{"30"}
		o.Timeout = 300 * time.Millisecond
	})
	w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"slow"}`)
	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d want 504", w.Code)
	}
	w2 := post(t, a, `{"jsonrpc":"2.0","id":2,"method":"slow"}`)
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-retire status=%d want 503", w2.Code)
	}
}

// TestCloseTerminatesChild: Close kills the child and frees the port.
func TestCloseTerminatesChild(t *testing.T) {
	a, err := New(Options{Command: "cat"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// Second close is a no-op.
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestPathSurface: exactly "/" (local expose root) and "/mcp" (relay
// backend path) reach the child; any other path is a 404 before the
// child sees it, so a published endpoint cannot sprout siblings.
func TestPathSurface(t *testing.T) {
	a := startEcho(t, nil)
	body := `{"jsonrpc":"2.0","id":1,"method":"probe"}`
	for _, p := range []string{"/", "/mcp"} {
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader(body))
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("path %s: status=%d, want 200", p, w.Code)
		}
	}
	for _, p := range []string{"/admin", "/v1/keys", "/mcp/extra", "//mcp"} {
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader(body))
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("path %s: status=%d, want 404", p, w.Code)
		}
	}
	if n := a.Spawned(); n != 1 {
		t.Fatalf("spawned=%d, want exactly 1", n)
	}
}

// TestMethodNotAllowed: only POST is served.
func TestMethodNotAllowed(t *testing.T) {
	a := startEcho(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", w.Code)
	}
}

// TestInterleavedNotificationBeforeReply: a child-generated notification
// arriving before the request's reply must be dropped, never consumed as
// the answer. The old next-line-is-the-reply logic returned the
// notification line here.
func TestInterleavedNotificationBeforeReply(t *testing.T) {
	a := startEcho(t, func(o *Options) {
		o.Command = "sh"
		o.Args = []string{"-c", `IFS= read -r req; echo '{"jsonrpc":"2.0","method":"note"}'; echo '{"jsonrpc":"2.0","id":1,"result":{}}'`}
	})
	w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !strings.Contains(got, `"id":1`) || strings.Contains(got, `"method":"note"`) {
		t.Fatalf("notification misattributed as reply: %q", got)
	}
}

// TestCancelledCallReleasesWaiter: a disconnected HTTP caller drops its
// waiter without disturbing the child or retiring the adapter.
func TestCancelledCallReleasesWaiter(t *testing.T) {
	a := startSilent(t, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"slow"}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { a.ServeHTTP(w, req); close(done) }()
	waitPending(t, a, "1") // caller is in flight; cancel the registered waiter
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled call held the adapter")
	}
	if a.broken.Load() {
		t.Fatal("cancelled caller retired a healthy adapter")
	}
}

// TestDuplicateIDRejected: a second in-flight call reusing an
// outstanding request id gets 400 immediately instead of stealing the
// first call's reply.
func TestDuplicateIDRejected(t *testing.T) {
	a := startSilent(t, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() { _ = a.Close() }()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		req := httptest.NewRequest(http.MethodPost, "/",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"slow"}`)).WithContext(ctx)
		a.ServeHTTP(httptest.NewRecorder(), req)
	}()
	waitPending(t, a, "1") // first call registered; duplicate id must be refused
	w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"slow"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate id status=%d body=%q, want 400", w.Code, w.Body.String())
	}
}

// TestParallelDistinctIDs: two concurrent calls receive their own
// replies, matched by id rather than by arrival order.
func TestParallelDistinctIDs(t *testing.T) {
	a := startEcho(t, nil)
	type res struct {
		code int
		body string
	}
	call := func(id int) res {
		w := post(t, a, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"m"}`, id))
		return res{w.Code, w.Body.String()}
	}
	var r1, r2 res
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r1 = call(7) }()
	go func() { defer wg.Done(); r2 = call(8) }()
	wg.Wait()
	if r1.code != http.StatusOK || !strings.Contains(r1.body, `"id":7`) {
		t.Fatalf("call 7: code=%d body=%q", r1.code, r1.body)
	}
	if r2.code != http.StatusOK || !strings.Contains(r2.body, `"id":8`) {
		t.Fatalf("call 8: code=%d body=%q", r2.code, r2.body)
	}
}

// TestNoisyFailingChild: a child that logs to stderr and exits without a
// reply cannot hang the adapter: stderr goes to the null device (no pipe
// to fill) and EOF-without-newline is a 502, not a clean completion.
func TestNoisyFailingChild(t *testing.T) {
	a := startEcho(t, func(o *Options) {
		o.Command = "ls"
		o.Args = []string{"/nonexistent-dir-xyz-ocliv"}
	})
	done := make(chan int, 1)
	go func() {
		done <- post(t, a, `{"jsonrpc":"2.0","id":1,"method":"probe"}`).Code
	}()
	select {
	case code := <-done:
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d want 502", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("noisy failing child hung the adapter")
	}
	// Child death retires the adapter: the next call fails closed with
	// 503 instead of queueing behind a dead pipe.
	deadline := time.Now().Add(5 * time.Second)
	for !a.broken.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if w := post(t, a, `{"jsonrpc":"2.0","id":2,"method":"probe"}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-crash status=%d want 503", w.Code)
	}
}
