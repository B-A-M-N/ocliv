package integration

// Adversarial HTTP-exchange termination properties (Finding 5). The
// early-full-response-vs-late-upload-failure row is pinned at the relay
// layer instead (TestHeldEndOnLateUploadFailure in internal/relay): the
// all-Go test stack cannot produce that interleave, because Go's client
// Transport does not surface a response head while its own request body is
// still streaming (verified with isolated stdlib probes). The tests here
// pin the end-to-end-reachable rows:
//   - cancelling stalled exchanges releases all product exchange state;
//   - a dropped call that reached the app must never execute twice.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestCancelWhileStalledLeaksNoGoroutines: repeated visitor cancels
// against a hanging upstream must leave goroutine counts flat. A
// per-exchange goroutine that outlives cancellation accumulates here.
func TestCancelWhileStalledLeaksNoGoroutines(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	hdrs := authedHeaders(cookie)
	hdrs["Origin"] = "http://" + h.host()
	// Warmup: a fast full cycle so lazy one-time background work settles
	// before the baseline.
	warm := h.visitorReq(t, http.MethodGet, "/headers", nil, hdrs)
	_, _ = io.Copy(io.Discard, io.LimitReader(warm.Body, 64*1024))
	warm.Body.Close()
	runtime.GC()
	time.Sleep(time.Second)
	runtime.GC()
	before := runtime.NumGoroutine()

	// Do blocks until the first response head, which a hanging upstream
	// never sends: run it async, let the exchange stall, then cancel
	// client-side. Without client cancellation the call would only
	// measure the fixture's own 10s timeout instead of cancellation.
	//
	// The client uses a 1s idle timeout and is closed at the end: the
	// shared harness client's default 90s keep-alive pool would
	// otherwise dominate the count with test-side residue, masking the
	// product behavior under measurement.
	client := &http.Client{
		Transport: &http.Transport{IdleConnTimeout: time.Second},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	t.Cleanup(func() {
		if tr, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
			tr.CloseIdleConnections()
		}
	})
	type doResult struct {
		resp *http.Response
		err  error
	}
	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.relaySrv.URL+"/accept-then-hang", strings.NewReader("stall"))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = h.host()
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		ch := make(chan doResult, 1)
		go func() {
			r, err := client.Do(req)
			ch <- doResult{r, err}
		}()
		time.Sleep(500 * time.Millisecond) // let the exchange stall upstream
		cancel()
		select {
		case r := <-ch:
			if r.err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(r.resp.Body, 1))
				r.resp.Body.Close()
			}
		case <-time.After(15 * time.Second):
			t.Fatal("cancelled request never returned")
		}
	}
	// Retention is bounded but slow: a cancelled exchange with a clean
	// upload and no head waits out the full 30s head timeout before its
	// head reader and agent handler drain (Finding: slow-drain window,
	// see assessment). stdlib HTTP keep-alive pools on both sides add up
	// to 90s of test-harness residue that is not product state, so a raw
	// goroutine count cannot pin the product property. Instead, count
	// only stacks executing product exchange code and require those to
	// reach zero past the head timeout; a separate gross bound catches
	// runaway growth of any kind.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if n := countExchangeGoroutines(); n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d product exchange goroutines never drained after cancel", countExchangeGoroutines())
		}
		time.Sleep(2 * time.Second)
	}
	if got := runtime.NumGoroutine(); got > before+60 {
		t.Fatalf("gross goroutine growth after cancel: %d vs baseline %d", got, before)
	}
}

// countExchangeGoroutines counts stacks currently executing per-exchange
// product code: the relay exchange machine (all in relay_http.go) and the
// agent per-stream handlers. Long-lived session machinery
// (registerSession, supervise, yamux loops, accept loops) is deliberately
// excluded: it is per-session, not per-exchange, and must persist while
// the agent stays attached. stdlib pool loops are excluded by construction.
func countExchangeGoroutines() int {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	body := string(buf[:n])
	count := 0
	start := 0
	for {
		idx := indexGoroutine(body[start:])
		if idx < 0 {
			break
		}
		start += idx
		end := start + 4096
		if end > len(body) {
			end = len(body)
		}
		if next := indexGoroutine(body[start+9:]); next >= 0 && start+9+next < end {
			end = start + 9 + next
		}
		stack := body[start:end]
		if strings.Contains(stack, "ocliv/internal/relay/relay_http.go") ||
			strings.Contains(stack, "serveLocalHTTP") ||
			strings.Contains(stack, "serveLocalWS") {
			count++
		}
		start = end
	}
	return count
}

func indexGoroutine(s string) int {
	return strings.Index(s, "goroutine ")
}

// TestDroppedCallExecutesAtMostOnce: a JSON-RPC call that reaches the app
// and whose visitor then vanishes must be processed exactly once — the
// tunnel never replays an uncertain delivery (E14). The test waits until
// execution is observed, drops the connection unread, then proves no
// second execution arrives.
func TestDroppedCallExecutesAtMostOnce(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	raw := shareRaw(t, h)
	const rpcBody = `{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{}}`
	// Baseline AFTER agent start: the agent's local readiness probe may
	// already have touched the app. The property is exactly-once
	// relative to that baseline — no replay of this delivery.
	before := app.hits.Load()
	addr := h.relaySrv.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := fmt.Sprintf("POST /mcp HTTP/1.1\r\nHost: %s\r\nX-Ocliv-Authorization: Bearer %s\r\n"+
		"Content-Type: application/json\r\nAccept: application/json\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		h.host(), raw, len(rpcBody), rpcBody)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	// Wait until the app has executed this call, then vanish without
	// reading the response.
	deadline := time.Now().Add(10 * time.Second)
	for app.hits.Load() < before+1 {
		if time.Now().After(deadline) {
			conn.Close()
			t.Fatal("app never executed the call")
		}
		time.Sleep(50 * time.Millisecond)
	}
	conn.Close()
	time.Sleep(2 * time.Second)
	if got := app.hits.Load(); got != before+1 {
		t.Fatalf("dropped call executed %d times, want exactly once", got-before)
	}
}
