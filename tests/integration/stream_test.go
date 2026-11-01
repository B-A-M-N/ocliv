package integration

// Stream-completion honesty (P0-05): truncated bodies and aborted uploads
// must surface as failures, never as cleanly completed exchanges.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"ocliv/internal/config"
	"ocliv/internal/limits"
)

func shrinkHeadTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := limits.FirstByteTimeout
	limits.FirstByteTimeout = d
	t.Cleanup(func() { limits.FirstByteTimeout = old })
}

// TestSlowUploadBeatsHeadTimeout: a valid paced upload taking far longer
// than FirstByteTimeout must still succeed when the app answers after the
// full body (adversarial Finding 2). Pre-fix the socket read deadline was
// armed at admission, so the head reader timed out mid-upload and the
// visitor got a false 504 for a healthy exchange.
func TestSlowUploadBeatsHeadTimeout(t *testing.T) {
	shrinkHeadTimeout(t, 300*time.Millisecond)
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	// Six paced 1 KiB writes, 150 ms apart: total ~0.9 s of steady
	// progress, every gap well under the 300 ms idle window. Pacing via
	// pipe writes (not read chunking) is deterministic regardless of
	// transport buffering.
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for i := 0; i < 6; i++ {
			time.Sleep(150 * time.Millisecond)
			if _, err := pw.Write(bytes.Repeat([]byte("u"), 1024)); err != nil {
				return
			}
		}
	}()
	hdrs := authedHeaders(cookie)
	hdrs["Origin"] = "http://" + h.host()
	resp := h.visitorReq(t, http.MethodPost, "/echo", pr, hdrs)
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("slow upload failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK || len(got) != 6<<10 {
		t.Fatalf("slow upload lost: status=%d bytes=%d, want 200 + 6144", resp.StatusCode, len(got))
	}
}

// TestUpstreamSilenceAfterUploadTimesOut: once the upload completes, the
// response first-byte deadline still applies — an upstream that never
// produces headers times out instead of hanging the visitor.
func TestUpstreamSilenceAfterUploadTimesOut(t *testing.T) {
	shrinkHeadTimeout(t, 300*time.Millisecond)
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	hdrs := authedHeaders(cookie)
	hdrs["Origin"] = "http://" + h.host()
	start := time.Now()
	resp := h.visitorReq(t, http.MethodPost, "/accept-then-hang", strings.NewReader("small"), hdrs)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("silent upstream status=%d, want 504", resp.StatusCode)
	}
	// The fixture hangs for 10 s: a prompt 504 proves the tunnel enforced
	// its own response deadline instead of waiting out the upstream.
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("silent upstream took %v, want a prompt head-timeout 504", elapsed)
	}
}

// TestPerLeaseStreamQuotaExhaustion (M13/G05): a lease holds at most
// MaxStreamsLease concurrent streams. The 65th concurrent request is
// rejected deterministically (503) without touching the app, and slots
// are released when in-flight exchanges end — a single lease cannot
// pin the relay, and recovery needs no restart. Held streams use
// client-owned pipes so the test releases them deterministically instead
// of waiting out a server-side timeout.
func TestPerLeaseStreamQuotaExhaustion(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	hdrs := authedHeaders(cookie)
	hdrs["Origin"] = "http://" + h.host()
	type heldStream struct {
		resp *http.Response
		pw   *io.PipeWriter
		done chan struct{}
	}
	held := make([]*heldStream, 0, 64)
	for i := 0; i < 64; i++ {
		pr, pw := io.Pipe()
		hs := &heldStream{pw: pw, done: make(chan struct{})}
		go func() {
			defer close(hs.done)
			hs.resp = h.visitorReq(t, http.MethodPost, "/hold-upload", pr, hdrs)
		}()
		held = append(held, hs)
	}
	release := func() {
		for _, hs := range held {
			_ = hs.pw.Close()
		}
		for _, hs := range held {
			<-hs.done
			if hs.resp != nil {
				_, _ = io.Copy(io.Discard, hs.resp.Body)
				_ = hs.resp.Body.Close()
			}
		}
	}
	defer release()

	deadline := time.Now().Add(20 * time.Second)
	for {
		if app.postHits.Load() >= 64 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/64 streams reached the app", app.postHits.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
	before := app.postHits.Load()
	resp := h.visitorReq(t, http.MethodPost, "/echo", strings.NewReader("x"), hdrs)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over-quota status=%d, want 503", resp.StatusCode)
	}
	if got := app.postHits.Load(); got != before {
		t.Fatalf("rejected request reached the app (%d hits)", got-before)
	}

	release()
	held = nil
	deadline = time.Now().Add(20 * time.Second)
	for {
		r := h.visitorReq(t, http.MethodPost, "/echo", strings.NewReader("ok"), hdrs)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if r.StatusCode == http.StatusOK && string(body) == "ok" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery after release: last status=%d", r.StatusCode)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestEarlyRejectionSurfaces: a backend that rejects a 5 MiB upload
// without reading it must surface its 413. Pre-fix the relay never reads
// the waiting response (blocked writing an upload nobody consumes) and
// substitutes 502 (P0-06).
func TestEarlyRejectionSurfaces(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	body := bytes.Repeat([]byte("u"), 5<<20)
	hdrs := authedHeaders(cookie)
	hdrs["Origin"] = "http://" + h.host()
	resp := h.visitorReq(t, "POST", "/reject-early", bytes.NewReader(body), hdrs)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("early rejection lost: status %d", resp.StatusCode)
	}
}

// TestEarlyResponseDuringUpload: a 5 MiB upload racing a 2 MiB response
// that ignores the upload must complete on both sides. Pre-fix both
// directions stall on full yamux windows and the visitor times out (P0-06).
func TestEarlyResponseDuringUpload(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	body := bytes.Repeat([]byte("v"), 5<<20)
	hdrs := authedHeaders(cookie)
	hdrs["Origin"] = "http://" + h.host()
	resp := h.visitorReq(t, "POST", "/stream-while-ignoring", bytes.NewReader(body), hdrs)
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		t.Fatalf("response stream failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK || len(got) != 2<<20 {
		t.Fatalf("status=%d bytes=%d, want 200 + 2MiB", resp.StatusCode, len(got))
	}
}

// TestTruncatedBackendBodyAbortsDelivery: a backend that declares 1 MiB
// but dies after 100 KiB must not produce a clean 200 with a short body.
// The visitor must observe a truncated delivery (read error), proving the
// relay did not fabricate a clean end.
func TestTruncatedBackendBodyAbortsDelivery(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	resp := h.visitorReq(t, "GET", "/die-mid-body", nil, authedHeaders(cookie))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err == nil {
		t.Fatalf("truncated %d-byte body reported as clean completion", len(body))
	}
}

// TestAbortedUploadNeverCompletes: a client upload that stops short of its
// declared Content-Length must not be forwarded as a complete body. The
// relay must abort (400) instead of sending REQUEST_END, and the local app
// must observe a body error rather than a clean short EOF.
func TestAbortedUploadNeverCompletes(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	addr := h.relaySrv.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Chunked upload with no declared length: send one 1000-byte chunk,
	// then half-close without the terminal chunk. Go's length enforcement
	// cannot catch this; only honest abort signaling can (P0-05).
	req := fmt.Sprintf("POST /upload-report HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n"+
		"Origin: http://%s\r\n"+
		"Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n"+
		"Connection: close\r\n\r\n", h.host(), cookie, h.host())
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "3e8\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		t.Fatal(err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if err := tc.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := io.ReadAll(conn)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	status := strings.SplitN(string(raw), "\r\n", 2)[0]
	if !strings.Contains(status, "400") {
		t.Fatalf("aborted upload: want 400, got %q", status)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		n, clean, saw := app.uploadOutcome()
		if saw {
			if clean {
				t.Fatalf("local app saw clean EOF on %d-byte truncated upload", n)
			}
			if n >= 100000 {
				t.Fatalf("local app received %d bytes of a 1000-byte upload", n)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("local app never observed the upload")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestVisitorCancelMidStreamKeepsTunnelHealthy: a visitor that cancels a
// committed 5 MiB stream mid-body must observe a read error (never a clean
// completion), and the tunnel must keep serving afterwards: cancellation
// tears the exchange down without corrupting the session (E06).
func TestVisitorCancelMidStreamKeepsTunnelHealthy(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.relaySrv.URL+"/big", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = h.host()
	for k, v := range authedHeaders(cookie) {
		req.Header.Set(k, v)
	}
	req.Header.Set("Origin", "http://"+h.host())
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 4096)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		// Head never even arrived: still a failure to deliver, not a
		// clean completion; the tunnel-health assertion below decides.
		resp.Body.Close()
		t.Fatalf("no stream bytes before cancel: %v", err)
	}
	cancel()
	_, err = io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	resp.Body.Close()
	if err == nil {
		t.Fatalf("cancelled stream reported clean completion")
	}
	// The tunnel must be unimpaired: a fresh request on the same lease
	// completes fully with correct content.
	follow := h.visitorReq(t, http.MethodGet, "/headers", nil, authedHeaders(cookie))
	defer follow.Body.Close()
	if follow.StatusCode != http.StatusOK {
		t.Fatalf("post-cancel request status=%d, want 200", follow.StatusCode)
	}
	if got := readAll(t, follow.Body); !strings.Contains(got, `"app_auth":""`) {
		t.Fatalf("post-cancel follow-up status=%d body=%q", follow.StatusCode, got)
	}
	// Stop the agent before the deferred server closes run: a cancelled
	// bulk download can leave the agent pump blocked on a dead yamux
	// window, which otherwise stalls teardown (see residual note below).
	h.cancel()
}

// TestTTLMidStreamAbortsDelivery: a lease whose TTL expires after the
// response head commits but before the body completes must tear the
// delivery down, never report it clean (R4, P0-05).
func TestTTLMidStreamAbortsDelivery(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{TTLSeconds: 300})
	cookie := redeem(t, h)
	// Force the TTL to lapse 1s from now: the head (instant) commits
	// before expiry, the body (4s stall) outlives it.
	exp := time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	if _, err := h.db.SQL().Exec(`UPDATE leases SET expires_at=? WHERE id=?`, exp, h.attached.LeaseID); err != nil {
		t.Fatal(err)
	}

	resp := h.visitorReq(t, http.MethodGet, "/slow-body", nil, authedHeaders(cookie))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("head committed before TTL: status=%d, want 200", resp.StatusCode)
	}
	if _, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)); err == nil {
		t.Fatalf("post-TTL body delivered as clean completion")
	}
}
