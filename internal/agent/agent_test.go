package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"ocliv/internal/config"
	"ocliv/internal/protocol"
)

// TestStreamReaderSurfacesAbortAsError: transport failures, aborts, and
// malformed frames must surface as errors, never as a clean EOF that would
// let the local app process a truncated body as complete (P0-05).
// A proper REQUEST_END still ends the body cleanly.
// leaseIntentReady must reflect the local service at (re)connect time:
// up -> ready, down -> not ready. A hardcoded true would let a resume
// claim a reverified local service it never checked (P1-09).
func TestLeaseIntentReadyReflectsLocal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	up := &Runner{Target: strings.TrimPrefix(srv.URL, "http://")}
	if !up.leaseIntentReady() {
		t.Fatal("live local target reported not ready")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	down := &Runner{Target: deadAddr}
	if down.leaseIntentReady() {
		t.Fatal("dead local target reported ready")
	}
}

// saveLease must replace the lease record atomically: a crash mid-write
// must leave either the old or the new complete file, never torn JSON.
// An in-place truncation keeps the same inode; an atomic rename swaps it.
func TestSaveLeaseReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	rn := &Runner{Cfg: config.Agent{DataDir: dir, Port: 3000}}
	rn.saveLease(Attached{LeaseID: "l1", Hostname: "h", URL: "u", AccessMode: "private", Generation: 1})
	p := filepath.Join(dir, config.LeaseStoreDir, "l1.json")
	fi1, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	rn.saveLease(Attached{LeaseID: "l1", Hostname: "h", URL: "u", AccessMode: "private", Generation: 2})
	fi2, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(fi1, fi2) {
		t.Fatal("lease record updated in place; a crash could leave torn JSON")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"generation":2`) {
		t.Fatalf("lease record content = %s, want generation 2", raw)
	}
	if fi2.Mode().Perm() != 0o600 {
		t.Fatalf("lease record perms = %o, want 600", fi2.Mode().Perm())
	}
}

func TestStreamReaderSurfacesAbortAsError(t *testing.T) {
	// Abort frame -> error, not EOF.
	c1, c2 := net.Pipe()
	go func() {
		_ = protocol.WriteFrame(c2, protocol.FAbort, []byte(`{}`))
	}()
	sr := &streamReader{stream: c1}
	if _, err := sr.Read(make([]byte, 1024)); err == nil || err == io.EOF {
		t.Fatalf("abort masked as clean end: %v", err)
	}
	c1.Close()
	c2.Close()

	// Malformed bytes + close -> error, not EOF.
	d1, d2 := net.Pipe()
	go func() {
		_, _ = d2.Write([]byte{0xFF, 0x00, 0x01})
		d2.Close()
	}()
	sr2 := &streamReader{stream: d1}
	if _, err := sr2.Read(make([]byte, 1024)); err == nil || err == io.EOF {
		t.Fatalf("malformed frame masked as clean end: %v", err)
	}
	d1.Close()

	// Data then REQUEST_END -> data, then clean EOF (behavior preserved).
	e1, e2 := net.Pipe()
	go func() {
		_ = protocol.WriteFrame(e2, protocol.FRequestData, []byte("hello"))
		endRaw, _ := protocol.MarshalJSON(protocol.EndFrame{Type: "request_end"})
		_ = protocol.WriteFrame(e2, protocol.FRequestEnd, endRaw)
	}()
	sr3 := &streamReader{stream: e1}
	buf := make([]byte, 1024)
	n, err := sr3.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("data frame: n=%d err=%v", n, err)
	}
	if _, err := sr3.Read(buf); err != io.EOF {
		t.Fatalf("REQUEST_END must end cleanly, got %v", err)
	}
	e1.Close()
	e2.Close()
}

// TestProbeLocalRequiresHTTP: a bare TCP listener with no HTTP stack must
// NOT count as local readiness (AS-023/V2). Only an actual HTTP response
// passes, and a closed port fails.
func TestProbeLocalRequiresHTTP(t *testing.T) {
	if err := ProbeLocal("127.0.0.1:1", 2*time.Second); err == nil {
		t.Fatal("closed port passed the local probe")
	}

	// Bare TCP listener that never speaks HTTP.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without responding.
			go func() { <-time.After(10 * time.Second); c.Close() }()
		}
	}()
	if err := ProbeLocal(ln.Addr().String(), 2*time.Second); err == nil {
		t.Fatal("bare TCP listener passed the local HTTP probe")
	}

	// A real (even error-status) HTTP response proves a listener.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	target := srv.Listener.Addr().String()
	if err := ProbeLocal(target, 2*time.Second); err != nil {
		t.Fatalf("HTTP listener failed the local probe: %v", err)
	}
}

// TestProbeLocalDoesNotFollowRedirects: a redirect is itself proof of a
// listener. The probe must not follow it elsewhere (R3): following could
// leak the probe or misreport a foreign service as local readiness.
func TestProbeLocalDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Point at a closed port: following would fail, not-following passes.
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
	}))
	defer srv.Close()
	target := srv.Listener.Addr().String()
	if err := ProbeLocal(target, 2*time.Second); err != nil {
		t.Fatalf("redirecting listener failed the local probe: %v", err)
	}
}

// TestWSBaseForRefusesPlaintextDowngrade: https maps to wss, loopback http
// maps to ws, and remote plaintext (or garbage) is an error, never a
// silent ws downgrade (B02).
func TestWSBaseForRefusesPlaintextDowngrade(t *testing.T) {
	ok, err := wsBaseFor("https://relay.example.com")
	if err != nil || ok != "wss://relay.example.com" {
		t.Fatalf("https: got %q, %v", ok, err)
	}
	ok, err = wsBaseFor("http://127.0.0.1:8443/")
	if err != nil || ok != "ws://127.0.0.1:8443" {
		t.Fatalf("loopback http: got %q, %v", ok, err)
	}
	for _, bad := range []string{
		"http://203.0.113.9:8443",
		"http://relay.example.com",
		"ws://relay.example.com",
		"notaurl",
		"",
	} {
		if _, err := wsBaseFor(bad); err == nil {
			t.Fatalf("%q: want downgrade refusal, got nil error", bad)
		}
	}
}

// TestIsPermanentUsesTypedReasons: retry classification must follow the
// typed Permanent marker, not message wording (P2). A message that merely
// mentions a credential-adjacent word (e.g. a network error naming an
// "enrollment office") must stay retryable; only a wrapped Permanent
// error — however deeply nested — stops retries.
func TestIsPermanentUsesTypedReasons(t *testing.T) {
	if IsPermanent(nil) {
		t.Fatal("nil classified permanent")
	}
	if !IsPermanent(Permanent(fmt.Errorf("enrollment revoked"))) {
		t.Fatal("typed permanent error not recognized")
	}
	if !IsPermanent(fmt.Errorf("attach: %w", Permanent(errors.New("denied")))) {
		t.Fatal("wrapped typed permanent error not recognized")
	}
	if IsPermanent(errors.New("relay unreachable: enrollment office network down")) {
		t.Fatal("message wording classified permanent without a typed reason")
	}
	if IsPermanent(errors.New("agent lease permanently denied by relay")) {
		t.Fatal("bare message classified permanent without a typed reason")
	}
}

// TestChallengeDenialClassification: a 401 challenge (revoked/unknown key)
// must surface as a permanent error so the runner stops instead of
// retrying forever (F09); 429/5xx stay retryable with backoff.
func TestChallengeDenialClassification(t *testing.T) {
	for _, tc := range []struct {
		status    int
		permanent bool
	}{
		{http.StatusUnauthorized, true},
		{http.StatusBadRequest, true},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("denied"))
		}))
		rn := &Runner{Cfg: config.Agent{RelayURL: srv.URL}, KeyID: "key-test"}
		err := rn.once(context.Background())
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: want error", tc.status)
		}
		if got := IsPermanent(err); got != tc.permanent {
			t.Fatalf("status %d: permanent=%v want %v (%v)", tc.status, got, tc.permanent, err)
		}
	}
}

// A persistence failure must surface, never vanish: without a durable
// lease record the tunnel can neither resume nor be closed, so the caller
// (attach path) fails the attach instead of running stranded.
func TestSaveLeaseErrorSurfaced(t *testing.T) {
	// A regular file where the data directory should be: no temp file
	// can be created inside it.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rn := &Runner{Cfg: config.Agent{DataDir: blocker, Port: 3000}}
	if err := rn.saveLease(Attached{LeaseID: "l1"}); err == nil {
		t.Fatal("saveLease to an unwritable data dir succeeded")
	}
	// No persistence configured is not an error.
	rnFree := &Runner{Cfg: config.Agent{Port: 3000}}
	if err := rnFree.saveLease(Attached{LeaseID: "l1"}); err != nil {
		t.Fatalf("saveLease without data dir: %v", err)
	}
}

// TestServeLeavesNoWaiterPerSession (P1-6): 100 consecutive session
// lifetimes under one live runner context must not accumulate a waiter
// goroutine per session. The cancellation watcher belongs to the
// session, not the runner.
func TestServeLeavesNoWaiterPerSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rn := &Runner{}
	att := Attached{LeaseID: "lse-1", Generation: 1}
	serveOnce := func() {
		t.Helper()
		a, b := net.Pipe()
		ys, err := yamux.Server(b, yamux.DefaultConfig())
		if err != nil {
			a.Close()
			b.Close()
			t.Fatal(err)
		}
		_ = a.Close() // session ends immediately; AcceptStream fails
		_ = rn.serve(ctx, ys, att)
		_ = ys.Close()
		_ = b.Close()
	}
	serveOnce() // warm up yamux internals out of the measurement
	before := runtime.NumGoroutine()
	const sessions = 100
	for i := 0; i < sessions; i++ {
		serveOnce()
	}
	// Leaked waiters never exit while ctx lives; allow a short settle
	// for legitimate transient goroutines, then require bounded growth.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := runtime.NumGoroutine(); got <= before+5 {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("goroutines grew from %d to %d after %d sessions", before, got, sessions)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Two independent tunnels under one account must not clobber each other:
// saving lease B must leave lease A resumable by its own identity, and a
// changed deployment identity (port, mode, relay) must not resume the
// old lease (P1-7).
func TestConcurrentTunnelsKeepSeparateLeases(t *testing.T) {
	dir := t.TempDir()
	mk := func(port int, mode, name string, public bool) *Runner {
		return &Runner{
			Cfg:   config.Agent{DataDir: dir, RelayURL: "https://relay.example.test", Port: port, AccessMode: mode, Name: name, Public: public},
			KeyID: "key-abc",
		}
	}
	a := mk(3000, "", "", false)
	if err := a.saveLease(Attached{LeaseID: "lse-a", Hostname: "a.t", URL: "https://a", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	b := mk(3001, "", "", false)
	if err := b.saveLease(Attached{LeaseID: "lse-b", Hostname: "b.t", URL: "https://b", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	if got := mk(3000, "", "", false).resumeLeaseID(); got != "lse-a" {
		t.Fatalf("tunnel A resume = %q, want lse-a", got)
	}
	if got := mk(3001, "", "", false).resumeLeaseID(); got != "lse-b" {
		t.Fatalf("tunnel B resume = %q, want lse-b", got)
	}
	// Changed identity must not resume the old lease: different port,
	// flipped access mode, renamed tunnel, and moved relay each miss.
	if got := mk(3002, "", "", false).resumeLeaseID(); got != "" {
		t.Fatalf("wrong-port resume = %q, want empty", got)
	}
	if got := mk(3000, "mcp_upstream_oauth", "", false).resumeLeaseID(); got != "" {
		t.Fatalf("changed-mode resume = %q, want empty", got)
	}
	if got := mk(3000, "", "renamed", false).resumeLeaseID(); got != "" {
		t.Fatalf("renamed resume = %q, want empty", got)
	}
	other := &Runner{
		Cfg:   config.Agent{DataDir: dir, RelayURL: "https://other.example", Port: 3000},
		KeyID: "key-abc",
	}
	if got := other.resumeLeaseID(); got != "" {
		t.Fatalf("moved-relay resume = %q, want empty", got)
	}
}
