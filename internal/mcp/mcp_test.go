package mcp

import (
	"bufio"
	"context"
	"encoding/json"
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

func postCode(a *Adapter, body string) int {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w.Code
}

// TestAdapterEchoRoundTrip pins that one POST becomes one stdio message and
// the caller's JSON-RPC ID is restored in the reply.
func TestAdapterEchoRoundTrip(t *testing.T) {
	a := startEcho(t, nil)
	w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	var reply map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || reply["id"] != float64(1) || reply["method"] != "tools/list" {
		t.Fatalf("reply mismatch: %q err=%v", w.Body.String(), err)
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
		o.Args = []string{"-c", `IFS= read -r req; id=$(printf '%s' "$req" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'); echo "{\"jsonrpc\":\"2.0\",\"id\":\"$id\",\"result\":\"$MCP_ROLE\"}"`}
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
		o.Args = []string{"-c", `IFS= read -r req; id=$(printf '%s' "$req" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'); echo "{\"jsonrpc\":\"2.0\",\"id\":\"$id\",\"result\":\"$` + sentinelKey + `\"}"`}
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
		o.Args = []string{"-c", `IFS= read -r req; id=$(printf '%s' "$req" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'); echo "{\"jsonrpc\":\"2.0\",\"id\":\"$id\",\"result\":\"$PWD\"}"`}
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
func waitPending(t *testing.T, a *Adapter, _ string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		a.coord.mu.Lock()
		ok := len(a.coord.pending) > 0
		a.coord.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no in-flight waiter registered")
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

// Retirement has one observable publication point: once broken is stored,
// every newly admitted request must return 503 even while the reader is
// still unwinding pending calls. The callback barrier forces that exact
// interleaving instead of relying on scheduler luck.
func TestRetirementPublishesUnavailableBeforeCoordinatorCloses(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "retire.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(Options{Command: "cat", Args: []string{fifo}, MaxBodyBytes: 64, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	child, err := startChild(ctx, a.path, a.args, a.dir, a.env)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	a.child = child
	deathPublished := make(chan struct{})
	releaseDeath := make(chan struct{})
	var releaseOnce sync.Once
	a.coord = runCoordinator(child, a.maxBody, func() {
		a.broken.Store(true)
		close(deathPublished)
		<-releaseDeath
	})
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseDeath) })
		_ = a.Close()
		cancel()
	})

	firstDone := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"probe"}`))
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		firstDone <- w.Code
	}()
	waitPending(t, a, "1")
	f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(strings.Repeat("x", 1024) + "\n"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	select {
	case <-deathPublished:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not publish adapter retirement")
	}
	second := post(t, a, `{"jsonrpc":"2.0","id":2,"method":"probe"}`)
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("request during retirement callback status=%d want 503", second.Code)
	}
	releaseOnce.Do(func() { close(releaseDeath) })
	select {
	case code := <-firstDone:
		if code != http.StatusBadGateway {
			t.Fatalf("in-flight request status=%d want 502", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending request was not released after retirement")
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

// A child that never reads stdin must not hold an HTTP request beyond the
// same round-trip timeout used while waiting for its response.
func TestBlockedChildStdinWriteTimesOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  string
		args []string
	}{
		{name: "never reads", cmd: "sleep", args: []string{"30"}},
		{name: "reads only one byte", cmd: "sh", args: []string{"-c", "dd bs=1 count=1 of=/dev/null 2>/dev/null; sleep 30"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := startEcho(t, func(o *Options) {
				o.Command = tc.cmd
				o.Args = tc.args
				o.Timeout = 300 * time.Millisecond
				o.MaxBodyBytes = 2 << 20
			})
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"padding":"` + strings.Repeat("x", 1<<20) + `"}}`
			start := time.Now()
			w := post(t, a, body)
			if w.Code != http.StatusGatewayTimeout {
				t.Fatalf("blocked child write status=%d want 504", w.Code)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("blocked child write took %s, want bounded completion", elapsed)
			}
			if w := post(t, a, `{"jsonrpc":"2.0","id":2,"method":"ping"}`); w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status after blocked write retirement=%d want 503", w.Code)
			}
		})
	}
}

func TestConcurrentBlockedStdinWritersFinishByRequestDeadlines(t *testing.T) {
	a, err := New(Options{Command: "sleep", Args: []string{"30"}, Timeout: 300 * time.Millisecond, MaxBodyBytes: 2 << 20, MaxConcurrent: 4})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() { _ = a.Close() }()
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"padding":"` + strings.Repeat("x", 1<<20) + `"}}`
	started := time.Now()
	results := make(chan int, 2)
	for id := 1; id <= 2; id++ {
		id := id
		go func() { results <- postCode(a, fmt.Sprintf(body, id)) }()
	}
	for range 2 {
		select {
		case code := <-results:
			if code != http.StatusGatewayTimeout && code != http.StatusBadGateway && code != http.StatusServiceUnavailable {
				t.Fatalf("concurrent blocked writer status=%d, want timeout, child-exit, or fail-closed retirement", code)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent blocked writer exceeded request deadline")
		}
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("concurrent blocked writers took %s, want bounded completion", elapsed)
	}
}

func TestBlockedStdinWriteHonorsRequestCancellation(t *testing.T) {
	a := startEcho(t, func(o *Options) {
		o.Command = "sleep"
		o.Args = []string{"30"}
		o.Timeout = 5 * time.Second
		o.MaxBodyBytes = 2 << 20
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"padding":"` + strings.Repeat("x", 1<<20) + `"}}`
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)).WithContext(ctx)
		a.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	waitPending(t, a, "1")
	deadline := time.Now().Add(time.Second)
	for len(a.coord.wmu) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(a.coord.wmu) == 0 {
		t.Fatal("request did not start writing to child stdin")
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled request remained blocked on child stdin")
	}
	deadline = time.Now().Add(time.Second)
	for !a.broken.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !a.broken.Load() {
		t.Fatal("cancelled blocked request did not retire the child")
	}
}

func TestNotificationBlockedWriteHonorsCancellation(t *testing.T) {
	a := startEcho(t, func(o *Options) {
		o.Command = "sleep"
		o.Args = []string{"30"}
		o.Timeout = 5 * time.Second
		o.MaxBodyBytes = 2 << 20
	})
	ctx, cancel := context.WithCancel(context.Background())
	body := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"padding":"` + strings.Repeat("x", 1<<20) + `"}}`
	done := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)).WithContext(ctx)
		a.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for len(a.coord.wmu) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(a.coord.wmu) == 0 {
		t.Fatal("notification did not start writing to child stdin")
	}
	// The sleeping child never drains its pipe; allow the 1 MiB message to
	// fill it before cancellation so this covers a genuinely blocked write.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled notification remained blocked on child stdin")
	}
	if !a.broken.Load() {
		t.Fatal("cancelled blocked notification did not retire the child")
	}
}

// A multi-megabyte unterminated child frame is rejected before the adapter
// accumulates an unbounded line.
func TestMultiMegabyteUnterminatedChildOutputRetires(t *testing.T) {
	a := startEcho(t, func(o *Options) {
		o.Command = "sh"
		o.Args = []string{"-c", "head -c 8388608 /dev/zero"}
		o.MaxBodyBytes = 1024
	})
	deadline := time.Now().Add(3 * time.Second)
	for !a.broken.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !a.broken.Load() {
		t.Fatal("adapter did not retire after oversized unterminated output")
	}
	w := post(t, a, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status after oversized child output=%d want 503", w.Code)
	}
}

type countingUnterminatedReader struct{ bytesRead int }

func (r *countingUnterminatedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.bytesRead += len(p)
	return len(p), nil
}

// The line reader consumes only the configured frame bound plus one
// bufio fragment before rejecting an unterminated frame. This pins the
// allocation bound independently of process scheduling or heap noise.
func TestUnterminatedChildOutputReadBound(t *testing.T) {
	const maxBody = 1024
	const readBuffer = 64
	r := &countingUnterminatedReader{}
	retired := make(chan struct{})
	co := &coordinator{
		pending: make(map[string]chan coordResult), maxBody: maxBody,
		onDeath: func() { close(retired) },
	}
	co.readLoop(bufio.NewReaderSize(r, readBuffer))
	select {
	case <-retired:
	default:
		t.Fatal("oversized unterminated frame did not retire coordinator")
	}
	if r.bytesRead > maxBody+readBuffer {
		t.Fatalf("reader consumed %d bytes before rejection, cap is %d", r.bytesRead, maxBody+readBuffer)
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
		o.Args = []string{"-c", `IFS= read -r req; echo '{"jsonrpc":"2.0","method":"note"}'; echo "$req"`}
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

// Independent MCP clients may reuse the same JSON-RPC ID. Internal IDs keep
// replies attached to the originating caller even when the child responds in
// reverse order.
func TestConcurrentDuplicateIDsRemainIsolated(t *testing.T) {
	releaseFile := filepath.Join(t.TempDir(), "release-child")
	a := startEcho(t, func(o *Options) {
		o.Command = "sh"
		o.Args = []string{"-c", `IFS= read -r first || exit; IFS= read -r second || exit; while [ ! -e "$OCLIV_TEST_RELEASE" ]; do sleep 0.01; done; printf '%s\n' "$second"; printf '%s\n' "$first"`}
		o.Env = []string{"OCLIV_TEST_RELEASE=" + releaseFile}
	})
	defer a.Close()
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	secondDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstDone <- post(t, a, `{"jsonrpc":"2.0","id":1,"method":"call","params":{"client":"first"}}`)
	}()
	waitPendingCount(t, a, 1)
	go func() {
		secondDone <- post(t, a, `{"jsonrpc":"2.0","id":1,"method":"call","params":{"client":"second"}}`)
	}()
	waitPendingCount(t, a, 2)
	if err := os.WriteFile(releaseFile, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, second := <-firstDone, <-secondDone
	for _, result := range []struct {
		name string
		w    *httptest.ResponseRecorder
	}{
		{name: "first", w: first},
		{name: "second", w: second},
	} {
		if result.w.Code != http.StatusOK || !strings.Contains(result.w.Body.String(), `"id":1`) || !strings.Contains(result.w.Body.String(), `"client":"`+result.name+`"`) {
			t.Errorf("%s client received wrong reply: status=%d body=%q", result.name, result.w.Code, result.w.Body.String())
		}
	}
}

func waitPendingCount(t *testing.T, a *Adapter, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		a.coord.mu.Lock()
		got := len(a.coord.pending)
		a.coord.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pending calls never reached %d", want)
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
// to fill) and the failed request is rejected (502 during exchange, or
// 503 if child retirement wins before request admission).
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
		if code != http.StatusBadGateway && code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d want 502 during exchange or 503 after retirement", code)
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
