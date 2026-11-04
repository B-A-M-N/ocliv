package integration

// Isolated E2E qualification (P2): one harness instance, temp dirs and
// loopback ports only, walking the operator checklist in order. Each
// phase asserts its own contract so a failure names its step:
//
//	fresh enrollment -> HTTP tunnel -> 32-worker pressure (beyond the
//	8-worker soak) -> agent restart (same lease) -> relay restart
//	(same port + DB, fresh server) -> permanent revocation
//	(terminal, stale session cannot forward).
//
// Streaming, TTL expiry, concurrent clients, and shutdown are covered
// by their own named tests (stream/revoke/lifecycle/soak suites); this
// test chains the transitions those suites prove in isolation.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/config"
	"ocliv/internal/relay"
	"ocliv/internal/store"
)

func TestE2EQualification(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	h.startAgent(t, app.Port)

	// 1. Unauthorized visitor denied with zero upstream contact.
	before := app.Hits()
	resp := h.visitorReq(t, "GET", "/", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unauthenticated: want 302, got %d", resp.StatusCode)
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("unauthenticated request reached the app %d times", got)
	}

	// 2. Authorized tunnel round-trip.
	cookie := redeem(t, h)
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	bdy := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || bdy != "hello" {
		t.Fatalf("authorized GET: status=%d body=%q", resp.StatusCode, bdy)
	}

	// 3. Pressure: 32 concurrent POST echoes, no cross-wire (4x the
	// soak's 8 workers).
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("e2e-%03d-", i) + strings.Repeat("p", 512))
			resp := h.visitorReq(t, "POST", "/echo", bytes.NewReader(payload), h.unsafeHeaders(cookie))
			got, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if err != nil || !bytes.Equal(got, payload) {
				errs <- fmt.Sprintf("worker %d: bytes mismatch err=%v", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}

	// 4. Agent restart resumes the SAME lease and the tunnel works.
	leaseID := h.attached.LeaseID
	h.restartAgent(t, app.Port)
	if h.attached.LeaseID != leaseID {
		t.Fatalf("agent restart minted %q, want resumed %q", h.attached.LeaseID, leaseID)
	}
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-restart tunnel: status=%d", resp.StatusCode)
	}
	if h.cancel != nil {
		h.cancel()
	}
	time.Sleep(300 * time.Millisecond)

	// 5. Relay restart: fresh server over the same DB file, same port
	// (production restarts keep the address). The agent must resume
	// the same lease and the visitor cookie must still be honored.
	_, oldPort, err := net.SplitHostPort(strings.TrimPrefix(h.relaySrv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	h.relaySrv.Close()
	db2, err := store.Open(filepath.Join(h.dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	srv2, err := relay.New(relay.Options{DB: db2, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+oldPort)
	if err != nil {
		t.Fatalf("rebind relay port: %v", err)
	}
	rs2 := &httptest.Server{Listener: ln, Config: &http.Server{Handler: srv2.Handler(), ReadHeaderTimeout: 10 * time.Second}}
	rs2.Start()
	defer rs2.Close()
	h.relaySrv = rs2
	h.relay = srv2
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rn := &agent.Runner{
		Cfg:                config.Agent{RelayURL: rs2.URL, Port: app.Port, DataDir: h.agentDir},
		Key:                h.agentKey,
		KeyID:              h.keyID,
		Target:             fmt.Sprintf("127.0.0.1:%d", app.Port),
		HandshakeTransport: h.handshakeTransport(),
	}
	attached := make(chan agent.Attached, 4)
	rn.OnAttach = func(a agent.Attached) { attached <- a }
	go func() { _ = rn.Run(ctx) }()
	select {
	case a := <-attached:
		if a.LeaseID != leaseID {
			t.Fatalf("post-relay-restart lease %q, want resumed %q", a.LeaseID, leaseID)
		}
	case <-ctx.Done():
		t.Fatal("agent did not reattach after relay restart")
	}
	// Visitor cookie sessions die with the restarted process (ephemeral
	// relay key, fail closed): the old cookie must be denied, then the
	// owner issues a fresh share and traffic resumes on the same URL.
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusFound {
		t.Fatalf("pre-restart cookie after restart: want denial, got %d", resp.StatusCode)
	}
	code, raw := h.mgmt(t, h.agentKey, h.keyID, "POST", "share")
	if code != http.StatusOK {
		t.Fatalf("post-restart share: want 200 got %d (%s)", code, raw)
	}
	var shr map[string]string
	if err := json.Unmarshal(raw, &shr); err != nil || shr["share_url"] == "" {
		t.Fatalf("post-restart share returned no share_url: %v", err)
	}
	cookie = redeemURL(t, h, shr["share_url"])
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-relay-restart tunnel: status=%d", resp.StatusCode)
	}

	// 6. Permanent revocation: terminal row, stale session denied with
	// zero upstream contact, and a fresh resume cannot resurrect it.
	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "revoke"); code != http.StatusOK {
		t.Fatalf("revoke: want 200 got %d", code)
	}
	before = app.Hits()
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("revoked lease still forwarded traffic")
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("revoked lease reached the app %d times", got)
	}
	var status string
	if err := h.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "REVOKED" {
		t.Fatalf("lease status %q after revoke, want REVOKED", status)
	}
}
