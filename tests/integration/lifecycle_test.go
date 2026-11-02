// Lifecycle regression coverage for V1 (TTL/expiry), V3 (boot
// reconciliation), and V4 (terminal resume errors). Each test fails on the
// pre-fix behavior: TTL ignored, ACTIVE rows orphaned after restart, and
// revoked/expired/closed resume silently minting a replacement lease.
package integration

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ocliv/internal/config"
	"ocliv/internal/lease"
	"ocliv/internal/relay"
	"ocliv/internal/store"
)

// An offline publisher's route must deny without forwarding: after the
// agent image stops, visitor traffic gets 503 and the local app sees
// zero additional hits. A stale-but-registered route must never serve
// from a dead session or silently forward into the void.
func TestOfflineRouteDeniesWithoutForwarding(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{Public: true})
	resp := h.visitorReq(t, "GET", "/", nil, nil)
	if body := readAll(t, resp.Body); resp.StatusCode != http.StatusOK || body != "hello" {
		resp.Body.Close()
		t.Fatalf("public baseline: status=%d body=%q", resp.StatusCode, body)
	}
	resp.Body.Close()
	before := app.Hits()
	h.cancel() // stop the agent image; the session is gone
	denied := false
	deadline := time.Now().Add(20 * time.Second)
	for !denied && time.Now().Before(deadline) {
		resp := h.visitorReq(t, "GET", "/", nil, nil)
		readAll(t, resp.Body)
		resp.Body.Close()
		denied = resp.StatusCode == http.StatusServiceUnavailable
		if !denied {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if !denied {
		t.Fatal("offline route never denied with 503")
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("offline route forwarded to local app %d times", got)
	}
}

func leaseCount(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func leaseStatus(t *testing.T, db *store.DB, id string) string {
	t.Helper()
	var st string
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, id).Scan(&st); err != nil {
		t.Fatalf("lease %s: %v", id, err)
	}
	return st
}

// TestTTLExpiryDeniesTrafficAndResume: a lease created with --ttl must stop
// routing after expiry (404 like any expired hostname) and must never resume.
func TestTTLExpiryDeniesTrafficAndResume(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{TTLSeconds: 2})
	leaseID := h.attached.LeaseID

	cookie := redeem(t, h)
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-expiry: want 200 got %d", resp.StatusCode)
	}

	// Let the TTL lapse while the agent stays connected.
	time.Sleep(3 * time.Second)

	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("post-expiry route: want 404 got %d", resp.StatusCode)
	}
	if st := leaseStatus(t, h.db, leaseID); st != lease.StateExpired {
		t.Fatalf("post-expiry status: want EXPIRED got %q", st)
	}

	// Force a fresh resume attempt with the same lease id: the agent must
	// NOT get a replacement lease.
	h.cancel()
	time.Sleep(500 * time.Millisecond)
	n := leaseCount(t, h.db)
	if n != 1 {
		t.Fatalf("post-expiry resume minted a replacement lease: count=%d", n)
	}
}

// TestClosedResumeIsTerminal (V4): closing the owner lease while the agent is
// attached must not yield a silently minted replacement lease on reconnect.
func TestClosedResumeIsTerminal(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	origHost := h.attached.Hostname

	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "close"); code != http.StatusOK {
		t.Fatalf("close lease: want 200 got %d", code)
	}

	// The attached agent reconnects automatically with the same lease id.
	// Allow several backoff rounds, then assert no replacement was minted.
	deadline := time.Now().Add(12 * time.Second)
	for {
		if n := leaseCount(t, h.db); n != 1 {
			t.Fatalf("closed-lease resume minted a replacement: count=%d", n)
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	var host string
	if err := h.db.SQL().QueryRow(`SELECT hostname FROM leases`).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if host != origHost {
		t.Fatalf("hostname changed after close: %q -> %q", origHost, host)
	}
}

// TestExpiredLeaseAutoReplaced (P0-4): downtime beyond the TTL must not
// strand the publisher. Restarting with a stale local record must drop
// it after the relay's authoritative expired denial (4410) and attach a
// replacement lease — no manual lease-file surgery, no re-enrollment of
// a still-valid key. Pre-fix, the resume was denied as terminal and the
// CLI advised re-enrollment despite the valid key.
func TestExpiredLeaseAutoReplaced(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{TTLSeconds: 2})
	staleID := h.attached.LeaseID
	if staleID == "" {
		t.Fatal("no lease attached")
	}

	// Let the TTL lapse while the agent stays connected.
	time.Sleep(3 * time.Second)

	// Restart reusing the same data dir (stale record present), exactly
	// the post-crash shape: the runner must recover by itself.
	h.restartAgent(t, app.Port)
	if h.attached.LeaseID == "" {
		t.Fatal("restarted agent did not attach")
	}
	if h.attached.LeaseID == staleID {
		t.Fatalf("restarted agent resumed the expired lease %q", staleID)
	}
	store, err := config.OpenLeaseStore(h.agentDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Load(staleID); ok {
		t.Fatalf("stale lease record %q was not dropped after 4410 denial", staleID)
	}
}

// TestBootReconciliation (V3): a relay restart must move the orphaned ACTIVE
// row to RECONNECTING (never leave it ACTIVE with no session) and the same
// agent must resume the same hostname with a fenced generation.
func TestBootReconciliation(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	h.startAgent(t, app.Port)
	leaseID := h.attached.LeaseID
	origHost := h.attached.Hostname

	// Sanity: traffic flows before the crash.
	cookie := redeem(t, h)
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("pre-restart traffic: status=%d body=%q", resp.StatusCode, body)
	}

	// Simulate a crash: kill the listener. The old Server object keeps stale
	// in-memory state, so build a FRESH server over the same database file,
	// exactly like a restarted process would.
	h.relaySrv.Close()
	dbPath := filepath.Join(h.dir, "ocliv.db")
	db2, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	srv2, err := relay.New(relay.Options{DB: db2, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	_, oldPort, err := net.SplitHostPort(strings.TrimPrefix(h.relaySrv.URL, "http://"))
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

	// The orphaned ACTIVE row must be RECONNECTING immediately after boot,
	// before any agent reattaches.
	var st string
	if err := db2.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != lease.StateReconnecting {
		t.Fatalf("post-boot status: want RECONNECTING got %q", st)
	}
	// No traffic may route while no session is live.
	if code := probeRoute(t, srv2, origHost); code != http.StatusServiceUnavailable {
		t.Fatalf("post-restart route: want 503 got %d", code)
	}

	// A fresh agent image with the same key and lease file must resume the
	// SAME hostname with a fenced generation.
	h.restartAgent(t, app.Port)
	var g int64
	var s string
	_ = db2.SQL().QueryRow(`SELECT generation, status FROM leases WHERE id=?`, leaseID).Scan(&g, &s)
	if s != lease.StateActive || g != 2 {
		t.Fatalf("agent did not resume after restart (gen=%d status=%q)", g, s)
	}
	if h.attached.LeaseID != leaseID || h.attached.Hostname != origHost {
		t.Fatalf("resume changed identity: %+v", h.attached)
	}
	// Visitor cookie sessions are HMAC-bound to an ephemeral per-process
	// relay key ("random per relay"), so a restart fail-closes them: the
	// old cookie must be denied, and traffic resumes after the owner
	// issues a fresh share (verifier records survive in SQLite, spec 3.3).
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
	body = readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("post-restart traffic: status=%d body=%q", resp.StatusCode, body)
	}
	var host string
	_ = db2.SQL().QueryRow(`SELECT hostname FROM leases WHERE id=?`, leaseID).Scan(&host)
	if host != origHost {
		t.Fatalf("hostname changed across restart: %q -> %q", origHost, host)
	}
}

// redeemURL redeems a share link that did not come from the attach message.
func redeemURL(t *testing.T, h *harness, shareURL string) string {
	t.Helper()
	saved := h.attached
	h.attached.ShareURL = shareURL
	defer func() { h.attached = saved }()
	return redeem(t, h)
}

// probeRoute asks srv2's route table directly via a visitor-shaped request.
func probeRoute(t *testing.T, srv *relay.Server, host string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://x/", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}
