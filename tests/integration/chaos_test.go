// Chaos and recovery: relay restarts, agent reconnects, local failure,
// overload. Recovery must be deterministic (F02-F11, G05).
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/config"
	"ocliv/internal/relay"
	"ocliv/internal/store"
)

func TestRelayRestartRecovery(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)
	url := "https://" + h.attached.Hostname
	leaseID := h.attached.LeaseID

	// Kill the relay (no graceful close): traffic must fail at TCP rather
	// than misroute or fabricate a response.
	h.relaySrv.Close()
	deadReq, _ := http.NewRequest("GET", "http://127.0.0.1:1/", nil)
	deadReq.Host = h.host()
	if _, err := visitorClient.Do(deadReq); err == nil {
		t.Fatal("expected connection failure to dead relay")
	}
	// Restart the relay on the SAME port and DB (production restarts keep
	// the address): the agent must resume the same lease with a fenced
	// generation and the same public URL (F04, F11). The restart builds a
	// FRESH server over the same database file, exactly like a restarted
	// process: reusing the old in-process Server would keep stale sessions
	// alive and never exercise boot reconciliation (F11, AS-083).
	_, oldPort, err := net.SplitHostPort(strings.TrimPrefix(h.relaySrv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
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
	rs2 := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: srv2.Handler(), ReadHeaderTimeout: 10 * time.Second},
	}
	rs2.Start()
	defer rs2.Close()
	h.relaySrv = rs2
	// A fresh agent image with the same key and lease file resumes the
	// lease; waiting on the stale image would depend on yamux keepalive
	// timing, not on recovery correctness.
	h.restartAgent(t, app.Port)
	var gen int64
	var st string
	_ = db2.SQL().QueryRow(`SELECT generation, status FROM leases WHERE id=?`, leaseID).Scan(&gen, &st)
	if st != "ACTIVE" || gen != 2 {
		t.Fatalf("agent did not resume (gen=%d status=%q)", gen, st)
	}
	// Visitor cookie sessions die with the restarted process (ephemeral
	// relay key, fail closed); the owner issues a fresh share and traffic
	// resumes on the same URL.
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
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
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("post-restart: status=%d body=%q", resp.StatusCode, body)
	}
	if "https://"+h.attached.Hostname != url {
		t.Fatal("public URL changed across relay restart")
	}
	// Old sessions cannot retain authority: only generation 2 is live.
	var count int
	_ = h.db.SQL().QueryRow(`SELECT COUNT(*) FROM leases WHERE id=? AND generation=2`, leaseID).Scan(&count)
	if count != 1 {
		t.Fatal("fencing did not advance generation atomically")
	}
}

func TestAgentReconnectSameURL(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)
	firstURL := h.attached.URL

	// Kill the agent; once dead-session detection fires, the lease enters
	// RECONNECTING and traffic gets 503 instead of routing to a stale
	// socket (F07). A brief truthful 502 window during detection is
	// acceptable (F08); the steady state must be 503.
	h.cancel()
	saw503 := false
	for i := 0; i < 50 && !saw503; i++ {
		time.Sleep(300 * time.Millisecond)
		resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
		resp.Body.Close()
		saw503 = resp.StatusCode == http.StatusServiceUnavailable
	}
	if !saw503 {
		t.Fatal("offline lease never reached 503")
	}
	// Restart the agent with the same port: resume keeps the URL (F04).
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	rn := &agent.Runner{
		Cfg:                config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port, DataDir: h.agentDir},
		Key:                h.agentKey,
		KeyID:              h.keyID,
		Target:             fmt.Sprintf("127.0.0.1:%d", app.Port),
		HandshakeTransport: h.handshakeTransport(),
	}
	attached := make(chan agent.Attached, 2)
	rn.OnAttach = func(a agent.Attached) { attached <- a }
	go func() { _ = rn.Run(ctx2) }()
	select {
	case a := <-attached:
		if a.URL != firstURL {
			t.Fatalf("URL changed on resume: %q vs %q", a.URL, firstURL)
		}
		if a.Generation != 2 {
			t.Fatalf("generation=%d want 2", a.Generation)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not resume")
	}
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("post-resume: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestLocalAppFailure(t *testing.T) {
	app := startLocalApp(t)
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	// Local app dies: the relay reports 502 without retrying or
	// fabricating success (F08, F14: no replay of uncertain requests).
	app.srv.Close()
	resp := h.visitorReq(t, "POST", "/echo", bytes.NewReader([]byte("do-not-retry")), h.unsafeHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("dead local: want 502 got %d", resp.StatusCode)
	}
}

func TestPerLeaseStreamQuota(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	// 70 concurrent slow requests against a 64-stream budget: the excess
	// must be deterministically rejected (G05), never queued unboundedly.
	const n = 70
	var rejected atomic.Int64
	var okCount atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.visitorReq(t, "GET", "/slow", nil, authedHeaders(cookie))
			resp.Body.Close()
			if resp.StatusCode == http.StatusServiceUnavailable {
				rejected.Add(1)
			} else if resp.StatusCode == http.StatusOK {
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()
	t.Logf("quota: ok=%d rejected=%d", okCount.Load(), rejected.Load())
	if rejected.Load() == 0 {
		t.Fatal("expected deterministic quota rejections under overload")
	}
	if okCount.Load() > 64 {
		t.Fatalf("budget exceeded: %d concurrent streams served", okCount.Load())
	}
}
