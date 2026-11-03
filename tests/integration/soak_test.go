// Bounded sustained-traffic soak (Stage 6 operator-authorized run).
// SOAK_SECS controls duration (default 30s for the suite; longer for
// the qualification run, e.g. SOAK_SECS=300). 8 workers drive
// protected GET/POST traffic through a full relay+agent path; halfway
// the workers pause, the agent restarts, the visitor credential is
// re-redeemed, and traffic resumes on the same lease. Zero failed
// responses outside the controlled pause and bounded goroutine
// growth are required.
package integration

import (
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSoakBoundedTraffic(t *testing.T) {
	secs := 30
	if v := os.Getenv("SOAK_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1800 {
			secs = n
		}
	}
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	var headers atomic.Value // map[string]string, swapped on re-redeem
	headers.Store(authedHeaders(redeem(t, h)))

	// Warm up, then baseline goroutines.
	for i := 0; i < 20; i++ {
		resp := h.visitorReq(t, "GET", "/", nil, headers.Load().(map[string]string))
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("warmup status %d", resp.StatusCode)
		}
	}
	time.Sleep(2 * time.Second)
	baseGoroutines := runtime.NumGoroutine()

	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	var paused atomic.Bool
	var inFlight atomic.Int64
	var ok, fail int64
	var latTotal int64
	var codesMu sync.Mutex
	codes := map[int]int64{}
	worker := func(n int) {
		i := 0
		for time.Now().Before(deadline) {
			if paused.Load() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			i++
			inFlight.Add(1)
			start := time.Now()
			var resp *http.Response
			hdrs := headers.Load().(map[string]string)
			if i%8 == 0 {
				// Cookie-authenticated unsafe methods require the
				// exact same-origin proof browsers attach (C08);
				// without Origin the relay must 403.
				post := make(map[string]string, len(hdrs)+1)
				for k, v := range hdrs {
					post[k] = v
				}
				post["Origin"] = "http://" + h.host()
				resp = h.visitorReq(t, "POST", "/echo", strings.NewReader("soak-payload"), post)
			} else {
				resp = h.visitorReq(t, "GET", "/", nil, hdrs)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			inFlight.Add(-1)
			atomic.AddInt64(&latTotal, time.Since(start).Nanoseconds())
			codesMu.Lock()
			codes[resp.StatusCode]++
			codesMu.Unlock()
			if resp.StatusCode != http.StatusOK {
				atomic.AddInt64(&fail, 1)
			} else {
				atomic.AddInt64(&ok, 1)
			}
		}
	}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(n int) { defer wg.Done(); worker(n) }(w)
	}

	// Halfway: controlled pause, agent restart, re-redeem, resume.
	time.Sleep(time.Duration(secs/2) * time.Second)
	paused.Store(true)
	// Drain: no new requests issue while paused; wait for in-flight to
	// land before killing the agent, so the restart gap carries no
	// traffic and every counted response is a real verdict.
	drainUntil := time.Now().Add(10 * time.Second)
	for inFlight.Load() > 0 && time.Now().Before(drainUntil) {
		time.Sleep(20 * time.Millisecond)
	}
	if inFlight.Load() > 0 {
		t.Fatalf("in-flight requests did not drain: %d", inFlight.Load())
	}
	leaseID := h.attached.LeaseID
	h.restartAgent(t, app.Port)
	if h.attached.LeaseID != leaseID {
		t.Fatalf("resume changed lease: %q -> %q", leaseID, h.attached.LeaseID)
	}
	// The pre-restart visitor cookie survives resume (token generation
	// is unchanged; only the lease generation is fenced), so traffic
	// resumes with the same credential — no re-redeem.
	paused.Store(false)
	wg.Wait()

	denom := ok
	if denom == 0 {
		denom = 1
	}
	t.Logf("soak: %ds, ok=%d fail=%d avg_latency=%s codes=%v", secs, ok, fail,
		time.Duration(latTotal/denom), codes)
	if fail != 0 {
		t.Fatalf("soak failures outside controlled pause: %d (ok=%d)", fail, ok)
	}
	if ok == 0 {
		t.Fatal("soak completed no successful requests")
	}

	// Convergence: goroutines must settle back near baseline.
	time.Sleep(5 * time.Second)
	for i := 0; i < 10; i++ {
		runtime.GC()
		time.Sleep(200 * time.Millisecond)
	}
	growth := runtime.NumGoroutine() - baseGoroutines
	t.Logf("soak: goroutines baseline=%d now=%d growth=%d", baseGoroutines, runtime.NumGoroutine(), growth)
	if growth > 50 {
		t.Fatalf("goroutine growth unbounded: baseline=%d now=%d", baseGoroutines, runtime.NumGoroutine())
	}
}
