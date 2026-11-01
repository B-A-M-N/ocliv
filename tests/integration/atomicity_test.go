// Atomicity regression tests (Group 1: C07, R1, B09-fault, F12).
// Each test fails on the pre-fix behavior and passes afterward.
package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/config"
)

// TestCloseWinsOverConcurrentResume: hammering signed close while several
// agents resume the same lease must end terminal — closed status, no live
// session, no visitor traffic — never a resurrected ACTIVE lease (P0-02).
// Any resume landing after a close is fenced by the status predicate; a
// close landing after a resume re-closes unconditionally.
func TestCloseWinsOverConcurrentResume(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)
	leaseID := h.attached.LeaseID

	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-close status %d", resp.StatusCode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rn := &agent.Runner{
				Cfg:                config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port, DataDir: h.agentDir},
				Key:                h.agentKey,
				KeyID:              h.keyID,
				Target:             fmt.Sprintf("127.0.0.1:%d", app.Port),
				HandshakeTransport: h.handshakeTransport(),
			}
			_ = rn.Run(ctx)
		}()
	}
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 60; i++ {
		if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "close"); code != http.StatusOK {
			t.Fatalf("close %d: status %d", i, code)
		}
	}
	cancel()
	wg.Wait()

	var status string
	if err := h.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`,
		leaseID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "CLOSED" {
		t.Fatalf("terminal state lost: status %q", status)
	}
	before := app.Hits()
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("traffic reached local app after close")
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("closed lease served %d requests", got)
	}
}

func shareRaw(t *testing.T, h *harness) string {
	t.Helper()
	parts := strings.SplitN(h.attached.ShareURL, "#t=", 2)
	if len(parts) != 2 || parts[1] == "" {
		t.Fatal("no share token in attached message")
	}
	return parts[1]
}

func headerAuth(raw string) map[string]string {
	return map[string]string{"X-Ocliv-Authorization": "Bearer " + raw}
}

// TestSingleUseTokenNoDoubleSpend: 20 concurrent presents of a maxUses=1
// header token must yield exactly one success (C07 atomic consume).
func TestSingleUseTokenNoDoubleSpend(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	raw := shareRaw(t, h)

	const n = 20
	start := make(chan struct{})
	var ok int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp := h.visitorReq(t, "GET", "/", nil, headerAuth(raw))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt64(&ok, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok != 1 {
		t.Fatalf("single-use token honored %d times, want exactly 1", ok)
	}
}

// TestConcurrentResumeFencesDistinct: two simultaneous resumes of the same
// lease must land on distinct fenced generations, never a duplicated one
// (R1 atomic fencing).
func TestConcurrentResumeFencesDistinct(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	leaseID := h.attached.LeaseID

	attach := make(chan agent.Attached, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cfg := config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port, DataDir: h.agentDir}
			rn := &agent.Runner{Cfg: cfg, Key: h.agentKey, KeyID: h.keyID,
				Target: fmt.Sprintf("127.0.0.1:%d", app.Port), HandshakeTransport: h.handshakeTransport()}
			rn.OnAttach = func(a agent.Attached) { attach <- a }
			_ = rn.Run(ctx)
		}()
	}
	close(start)
	got := map[uint64]bool{}
	timeout := time.After(25 * time.Second)
	for len(got) < 2 {
		select {
		case a := <-attach:
			if a.LeaseID != leaseID {
				t.Fatalf("resume minted a new lease %q, want %q", a.LeaseID, leaseID)
			}
			got[a.Generation] = true
		case <-timeout:
			t.Fatalf("concurrent resumes did not both attach (gens=%v)", got)
		}
	}
	cancel()
	wg.Wait()
	if len(got) != 2 {
		t.Fatalf("concurrent resumes share a generation: %v", got)
	}
}

// tryAttach attempts one resume and reports whether attach happens in time.
func tryAttach(t *testing.T, h *harness, localPort int, d time.Duration) (agent.Attached, bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.Agent{RelayURL: h.relaySrv.URL, Port: localPort, DataDir: h.agentDir}
	rn := &agent.Runner{Cfg: cfg, Key: h.agentKey, KeyID: h.keyID,
		Target: fmt.Sprintf("127.0.0.1:%d", localPort), HandshakeTransport: h.handshakeTransport()}
	ch := make(chan agent.Attached, 1)
	rn.OnAttach = func(a agent.Attached) { ch <- a }
	go func() { _ = rn.Run(ctx) }()
	select {
	case a := <-ch:
		return a, true
	case <-time.After(d):
		return agent.Attached{}, false
	}
}

func leaseCountIs(t *testing.T, h *harness, want int, what string) {
	t.Helper()
	var n int
	if err := h.db.SQL().QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("%s: lease count=%d want %d (silent replacement?)", what, n, want)
	}
}

// TestCorruptLeaseRowFailClosed: unreadable lease state must fail closed,
// never mint a silent replacement (B09 store-fault + F12 corrupt timestamps).
func TestCorruptLeaseRowFailClosed(t *testing.T) {
	newSetup := func(t *testing.T) (int, *harness) {
		app := startLocalApp(t)
		t.Cleanup(func() { app.srv.Close() })
		h := newHarness(t)
		h.startAgent(t, app.Port)
		return app.Port, h
	}

	// Garbage in a scanned column (store fault shape): resume must not mint.
	{
		port, h := newSetup(t)
		defer h.db.Close()
		defer h.relaySrv.Close()
		leaseID := h.attached.LeaseID
		h.cancel()
		time.Sleep(300 * time.Millisecond)
		if _, err := h.db.SQL().Exec(`UPDATE leases SET port='bogus' WHERE id=?`, leaseID); err != nil {
			t.Fatal(err)
		}
		if _, ok := tryAttach(t, h, port, 8*time.Second); ok {
			t.Fatal("resume with unreadable lease row attached (fail-open mint?)")
		}
		leaseCountIs(t, h, 1, "unreadable row")
	}

	// Garbage expires_at: traffic must 404 and the row must EXPIRE, not route.
	{
		_, h := newSetup(t)
		defer h.db.Close()
		defer h.relaySrv.Close()
		cookie := redeem(t, h)
		leaseID := h.attached.LeaseID
		if _, err := h.db.SQL().Exec(`UPDATE leases SET expires_at='not-a-time' WHERE id=?`, leaseID); err != nil {
			t.Fatal(err)
		}
		resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("garbage expires_at: want 404 got %d", resp.StatusCode)
		}
		if st := leaseStatus(t, h.db, leaseID); st != "EXPIRED" {
			t.Fatalf("garbage expires_at: status=%q want EXPIRED", st)
		}
	}

	// Garbage reconnect_until: resume must be denied, no replacement.
	{
		port, h := newSetup(t)
		defer h.db.Close()
		defer h.relaySrv.Close()
		leaseID := h.attached.LeaseID
		h.cancel()
		time.Sleep(300 * time.Millisecond)
		if _, err := h.db.SQL().Exec(
			`UPDATE leases SET status='RECONNECTING', reconnect_until='garbage' WHERE id=?`, leaseID); err != nil {
			t.Fatal(err)
		}
		if _, ok := tryAttach(t, h, port, 8*time.Second); ok {
			t.Fatal("resume with unreadable reconnect_until attached")
		}
		leaseCountIs(t, h, 1, "unreadable reconnect_until")
	}
}
