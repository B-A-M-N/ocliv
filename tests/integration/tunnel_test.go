// Positive end-to-end coverage for the protected tunnel path.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/config"
)

func b64sig(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// redeem converts the attached share URL fragment into a session cookie.
func redeem(t *testing.T, h *harness) string {
	t.Helper()
	parts := strings.SplitN(h.attached.ShareURL, "#t=", 2)
	if len(parts) != 2 || parts[1] == "" {
		t.Fatal("no share token in attached message")
	}
	body, _ := json.Marshal(map[string]string{"token": parts[1]})
	req, err := http.NewRequest("POST", h.relaySrv.URL+"/_ocliv/redeem", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = h.host()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+h.host())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeem status %d", resp.StatusCode)
	}
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-ocliv-visitor" {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("no session cookie issued")
	}
	return cookie
}

func authedHeaders(cookie string) map[string]string {
	return map[string]string{"Cookie": cookie}
}

// unsafeHeaders adds the exact same-origin proof browsers attach to
// cookie-authenticated unsafe methods (C08).
func (h *harness) unsafeHeaders(cookie string) map[string]string {
	return map[string]string{"Cookie": cookie, "Origin": "http://" + h.host()}
}

// TestRedeemedCookieAbsentFromStoredRow (P0-4): the browser session
// bearer must never be readable from the database. After redemption the
// stored row may hold the lease binding and the HMAC verifier, but the
// cookie value itself must appear in no column — while the cookie still
// authorizes (storage secrecy must not break validation).
func TestRedeemedCookieAbsentFromStoredRow(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	cookie := redeem(t, h)
	parts := strings.SplitN(cookie, "=", 2)
	if len(parts) != 2 || parts[1] == "" {
		t.Fatalf("malformed session cookie %q", cookie)
	}
	bearer := parts[1]

	var id, leaseID, verifier, created, idleExp, absExp string
	var tokenGen int64
	var revoked sql.NullString
	err := h.db.SQL().QueryRow(
		`SELECT id, lease_id, token_generation, session_verifier,
			created_at, idle_expires_at, absolute_expires_at, revoked_at
		 FROM visitor_sessions`).Scan(
		&id, &leaseID, &tokenGen, &verifier, &created, &idleExp, &absExp, &revoked)
	if err != nil {
		t.Fatalf("session row not stored: %v", err)
	}
	for name, val := range map[string]string{
		"id": id, "lease_id": leaseID, "verifier": verifier,
		"created_at": created, "idle_expires": idleExp,
		"absolute_expires": absExp, "revoked": revoked.String,
	} {
		if val != "" && val == bearer {
			t.Fatalf("column %s stores the raw session bearer", name)
		}
	}
	if id == "" || verifier == "" {
		t.Fatalf("session row missing non-secret identity/verifier")
	}

	// The cookie must still authorize: secrecy without validation is a
	// denial of service, not a fix.
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeemed cookie rejected after storage fix: %d", resp.StatusCode)
	}
}

func TestProtectedTunnelEndToEnd(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	before := app.Hits()

	// 1. Unauthenticated visitor must NOT reach the local service (C01).
	resp := h.visitorReq(t, "GET", "/", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unauthenticated: want 302 to unlock, got %d", resp.StatusCode)
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("unauthenticated request reached local app %d times", got)
	}

	// 2. Redeem and make an authorized request.
	cookie := redeem(t, h)
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("authorized GET: status=%d body=%q", resp.StatusCode, body)
	}

	// 3. Header contract: app Host is local, proxy metadata is authoritative,
	// app Authorization passes through, relay cookie never leaks (E07, E08).
	resp = h.visitorReq(t, "GET", "/headers", nil, map[string]string{
		"Cookie":        cookie + "; session=abc123",
		"Authorization": "Bearer APP-TOKEN",
	})
	var hdrs map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&hdrs); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(hdrs["host"], "127.0.0.1:") {
		t.Fatalf("local Host not loopback: %q", hdrs["host"])
	}
	if hdrs["x-forwarded-host"] != h.host() {
		t.Fatalf("X-Forwarded-Host not authoritative: %q", hdrs["x-forwarded-host"])
	}
	if !strings.Contains(hdrs["cookie"], "session=abc123") {
		t.Fatalf("app cookie lost: %q", hdrs["cookie"])
	}
	if strings.Contains(hdrs["cookie"], "__Host-ocliv-visitor") {
		t.Fatalf("relay cookie leaked upstream: %q", hdrs["cookie"])
	}
	if hdrs["app_auth"] != "Bearer APP-TOKEN" {
		t.Fatalf("app Authorization not preserved: %q", hdrs["app_auth"])
	}
}

func TestConcurrentIsolation(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	// 50 concurrent distinct POST echoes must not cross-wire (E04).
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("payload-%03d-", i) + strings.Repeat("z", 1000))
			resp := h.visitorReq(t, "POST", "/echo", bytes.NewReader(payload), h.unsafeHeaders(cookie))
			got, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if err != nil {
				errs <- fmt.Sprintf("req %d: %v", i, err)
				return
			}
			if !bytes.Equal(got, payload) {
				errs <- fmt.Sprintf("req %d: %d bytes mismatched", i, len(got))
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestStreamingSSEAndLargeBodies(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	// Large upload streams through (2 MiB echo).
	big := bytes.Repeat([]byte("u"), 2<<20)
	resp := h.visitorReq(t, "POST", "/echo", bytes.NewReader(big), h.unsafeHeaders(cookie))
	got, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	resp.Body.Close()
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("large upload echo failed: err=%v got=%d bytes", err, len(got))
	}

	// Large download streams (5 MiB).
	resp = h.visitorReq(t, "GET", "/big", nil, authedHeaders(cookie))
	got, err = io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	resp.Body.Close()
	if err != nil || len(got) != 5<<20 {
		t.Fatalf("large download failed: err=%v got=%d bytes", err, len(got))
	}

	// SSE arrives incrementally (E11), not only at close.
	req, _ := http.NewRequest("GET", h.relaySrv.URL+"/sse", nil)
	req.Host = h.host()
	req.Header.Set("Cookie", cookie)
	start := time.Now()
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := resp.Body.Read(buf)
	first := time.Since(start)
	resp.Body.Close()
	if n == 0 || err != nil {
		t.Fatalf("no incremental SSE bytes: n=%d err=%v", n, err)
	}
	if first > 3*time.Second {
		t.Fatalf("SSE first flush too slow: %v", first)
	}
}

// TestNamedReclaimCutsOverTraffic: reclaiming a hostname while streams are
// active must move forwarding authority to the replacement lease: new
// traffic reaches the new destination, the old row is gone, and the old
// session is retired (P1-04).
func TestNamedReclaimCutsOverTraffic(t *testing.T) {
	app1 := startLocalApp(t)
	defer app1.srv.Close()
	app2 := startLocalApp(t)
	defer app2.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app1.Port, config.Agent{Name: "cutover"})
	cookie1 := redeem(t, h)
	oldID := h.attached.LeaseID

	// The agent's attach readiness probe (P1-09) hits the app before any
	// visitor traffic; measure only what the visitor request adds.
	preProbe := app1.Hits()
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie1))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-reclaim status %d", resp.StatusCode)
	}
	if got := app1.Hits() - preProbe; got != 1 {
		t.Fatalf("pre-reclaim app1 visitor hits=%d", got)
	}

	// Same tenant, new key, new destination, same hostname.
	k2, kid2 := h.enrollKey(t, "tenant-test")
	dir2, err := os.MkdirTemp("", "ocliv-agent-2-*")
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	rn := &agent.Runner{
		Cfg:                config.Agent{RelayURL: h.relaySrv.URL, Port: app2.Port, DataDir: dir2, Name: "cutover"},
		Key:                k2,
		KeyID:              kid2,
		Target:             fmt.Sprintf("127.0.0.1:%d", app2.Port),
		HandshakeTransport: h.handshakeTransport(),
	}
	attached2 := make(chan agent.Attached, 4)
	rn.OnAttach = func(a agent.Attached) { attached2 <- a }
	go func() { _ = rn.Run(ctx2) }()
	var a2 agent.Attached
	select {
	case a2 = <-attached2:
		if a2.LeaseID == oldID {
			t.Fatal("reclaim returned the same lease")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("reclaiming agent did not attach")
	}
	cookie2 := redeemURL(t, h, a2.ShareURL)

	// New traffic must reach the new destination (poll past registration).
	before1, before2 := app1.Hits(), app2.Hits()
	ok := false
	deadline := time.Now().Add(15 * time.Second)
	for !ok && time.Now().Before(deadline) {
		resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie2))
		body := readAll(t, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && body == "hello" {
			ok = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ok {
		t.Fatal("reclaimed hostname never served")
	}
	if got := app2.Hits() - before2; got < 1 {
		t.Fatal("reclaimed traffic did not reach the new destination")
	}
	if got := app1.Hits() - before1; got != 0 {
		t.Fatalf("retired lease served %d requests", got)
	}
	var n int
	if err := h.db.SQL().QueryRow(`SELECT COUNT(*) FROM leases WHERE id=?`,
		oldID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("old lease row survives reclamation")
	}
}

// A captured management mutation must not replay within the clock-skew
// window: the first identical signed request succeeds, the replay is
// rejected, and the same action with a fresh timestamp still works (P1-07).
func TestMgmtMutationReplayRejected(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	path := "/v1/agent/lease/" + h.attached.LeaseID + "/share"
	fire := func(ts time.Time, nonce string) int {
		msg := agent.MgmtMessage(h.keyID, "POST", path, ts, nonce)
		sig := ed25519.Sign(h.agentKey.Private(), msg)
		req, _ := http.NewRequest("POST", h.relaySrv.URL+path, nil)
		req.Host = h.relayHost
		req.Header.Set("X-Ocliv-Key", h.keyID)
		req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
		req.Header.Set("X-Ocliv-Nonce", nonce)
		req.Header.Set("X-Ocliv-Sig", b64sig(sig))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	mkNonce := func() string {
		nonce, err := agent.MgmtNonce()
		if err != nil {
			t.Fatal(err)
		}
		return nonce
	}
	ts := time.Now().UTC()
	// Same timestamp AND same nonce: the replay must be rejected even
	// though the timestamp alone cannot distinguish the two calls.
	replayed := mkNonce()
	if got := fire(ts, replayed); got != http.StatusOK {
		t.Fatalf("first share status %d", got)
	}
	if got := fire(ts, replayed); got == http.StatusOK {
		t.Fatal("replayed mutation accepted")
	}
	if got := fire(ts, mkNonce()); got != http.StatusOK {
		t.Fatalf("fresh-nonce mutation status %d", got)
	}
}

func TestRevokeTerminatesAccess(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke status %d", resp.StatusCode)
	}
	// Owner revokes via signed management call (C10).
	ts := time.Now().UTC()
	path := "/v1/agent/lease/" + h.attached.LeaseID + "/revoke"
	nonce, err := agent.MgmtNonce()
	if err != nil {
		t.Fatal(err)
	}
	msg := agent.MgmtMessage(h.keyID, "POST", path, ts, nonce)
	sig := ed25519.Sign(h.agentKey.Private(), msg)
	req, _ := http.NewRequest("POST", h.relaySrv.URL+path, nil)
	req.Host = h.relayHost
	req.Header.Set("X-Ocliv-Key", h.keyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig", b64sig(sig))
	mresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	mresp.Body.Close()
	if mresp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status %d", mresp.StatusCode)
	}
	// Active cookie session must now be denied without touching local (C10).
	before := app.Hits()
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("revoked session still authorized")
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("revoked session reached local app %d times", got)
	}
}

// TestRelayCredentialNeverForwarded: the visitor relay credential must be
// stripped before the local app, even when presented as a header (C04).
func TestRelayCredentialNeverForwarded(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	raw := shareRaw(t, h)

	resp := h.visitorReq(t, "GET", "/headers", nil, headerAuth(raw))
	var hdrs map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&hdrs); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("header auth: status=%d", resp.StatusCode)
	}
	if hdrs["relay_auth"] != "" {
		t.Fatalf("relay credential leaked to local app: %q", hdrs["relay_auth"])
	}
}
