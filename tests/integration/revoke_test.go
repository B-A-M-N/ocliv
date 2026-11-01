package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	"ocliv/internal/agent"
	"ocliv/internal/config"
	"ocliv/internal/limits"
	"ocliv/internal/relay"
)

// TestResumeModeChangeAllocatesFresh: resuming with a different access
// mode must never inherit the old mode — it allocates a new lease
// instead (P0-04). Public-to-protected and protected-to-public restarts
// both land on fresh leases with the requested mode.
func TestResumeModeChangeAllocatesFresh(t *testing.T) {
	for _, tc := range []struct {
		name        string
		firstPublic bool
		wantMode    string
	}{
		{"public_to_protected", true, "protected"},
		{"protected_to_public", false, "public"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := startLocalApp(t)
			defer app.srv.Close()
			h := newHarness(t)
			defer h.db.Close()
			defer h.relaySrv.Close()
			h.startAgentOpts(t, app.Port, config.Agent{Public: tc.firstPublic})
			oldID := h.attached.LeaseID

			if h.cancel != nil {
				h.cancel()
				time.Sleep(300 * time.Millisecond)
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			h.cancel = cancel
			cfg := config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port,
				DataDir: h.agentDir, Public: !tc.firstPublic}
			h.runAgent(t, ctx, cfg, h.agentDir, app.Port)

			if h.attached.LeaseID == oldID {
				t.Fatalf("mode change resumed same lease %q (mode inherited)", oldID)
			}
			if h.attached.AccessMode != tc.wantMode {
				t.Fatalf("mode change landed on %q, want %q", h.attached.AccessMode, tc.wantMode)
			}
		})
	}
}

// TestRevokeBlocksResume: after an owner revoke, the lease is terminal for
// the agent too — a later resume must be denied, not resurrect a live
// session on a revoked lease (P0-02, C10/B09). Deterministic: revoke leaves
// no status change pre-fix, so the fenced update re-activates the lease.
func TestRevokeBlocksResume(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	leaseID := h.attached.LeaseID

	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "revoke"); code != http.StatusOK {
		t.Fatalf("revoke status %d", code)
	}
	// Stop the evicted agent image so only the fresh resume attempt runs.
	if h.cancel != nil {
		h.cancel()
		time.Sleep(300 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rn := &agent.Runner{
		Cfg:                config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port, DataDir: h.agentDir},
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
		t.Fatalf("revoked lease resurrected: lease %s gen %d", a.LeaseID, a.Generation)
	case <-ctx.Done():
	}
	var status string
	if err := h.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`,
		leaseID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status == "ACTIVE" {
		t.Fatal("revoked lease row reads ACTIVE")
	}
}

// TestOperatorTakedownPublicLease: the documented operator procedure must
// also stop an active --public tunnel, which skips visitor authentication
// entirely. New public requests must be denied without reaching localhost.
func TestOperatorTakedownPublicLease(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{Public: true})
	if h.attached.AccessMode != "public" {
		t.Fatalf("mode=%q want public", h.attached.AccessMode)
	}

	resp := h.visitorReq(t, "GET", "/", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-takedown public status %d", resp.StatusCode)
	}

	// Operator procedure exactly as documented in docs/OPERATOR.md.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, q := range []struct {
		query string
		args  []any
	}{
		{`UPDATE access_tokens SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`, []any{now, h.attached.LeaseID}},
		{`UPDATE visitor_sessions SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`, []any{now, h.attached.LeaseID}},
		{`UPDATE leases SET token_generation=token_generation+1 WHERE id=?`, []any{h.attached.LeaseID}},
		{`UPDATE leases SET status='REVOKED' WHERE id=?`, []any{h.attached.LeaseID}},
		{`UPDATE agent_keys SET status='revoked' WHERE id=?`, []any{h.keyID}},
	} {
		if _, err := h.db.SQL().Exec(q.query, q.args...); err != nil {
			t.Fatalf("operator takedown statement failed: %v", err)
		}
	}
	h.db.Audit("operator", "", h.attached.LeaseID, "takedown", "ok", "compromised key revoked by operator")

	before := app.Hits()
	resp = h.visitorReq(t, "GET", "/", nil, nil)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("public tunnel still serving after operator takedown")
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("revoked public tunnel reached local app %d times", got)
	}
}

// TestOperatorTakedown: the documented operator procedure for a compromised
// agent key (direct, audited DB revocation identical to the agent-signed
// handler's statements) must deny visitor traffic immediately without a
// relay restart, and must deny every later attach/resume with that key
// (B09, C10). Only already-established in-flight streams on the live agent
// session drain naturally; full immediacy there needs a relay restart
// (residual risk, see final report).
func TestOperatorTakedown(t *testing.T) {
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
		t.Fatalf("pre-takedown status %d", resp.StatusCode)
	}

	// Operator procedure: same statements as the agent-signed revoke
	// handler, plus the key itself, with an explicit audit row (H04).
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, q := range []struct {
		query string
		args  []any
	}{
		{`UPDATE access_tokens SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`, []any{now, h.attached.LeaseID}},
		{`UPDATE visitor_sessions SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`, []any{now, h.attached.LeaseID}},
		{`UPDATE leases SET token_generation=token_generation+1 WHERE id=?`, []any{h.attached.LeaseID}},
		{`UPDATE leases SET status='REVOKED' WHERE id=?`, []any{h.attached.LeaseID}},
		{`UPDATE agent_keys SET status='revoked' WHERE id=?`, []any{h.keyID}},
	} {
		if _, err := h.db.SQL().Exec(q.query, q.args...); err != nil {
			t.Fatalf("operator takedown statement failed: %v", err)
		}
	}
	h.db.Audit("operator", "", h.attached.LeaseID, "takedown", "ok", "compromised key revoked by operator")

	// Visitor traffic with the old credential is denied immediately, and
	// never reaches the local app (C10, no relay restart).
	before := app.Hits()
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("operator-revoked credential still authorized")
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("operator-revoked credential reached local app %d times", got)
	}

	// The compromised key can never attach or resume again (B09).
	if h.cancel != nil {
		h.cancel()
		time.Sleep(300 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rn := &agent.Runner{
		Cfg:                config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port, DataDir: h.agentDir},
		Key:                h.agentKey,
		KeyID:              h.keyID,
		Target:             fmt.Sprintf("127.0.0.1:%d", app.Port),
		HandshakeTransport: h.handshakeTransport(),
	}
	attached := make(chan agent.Attached, 4)
	rn.OnAttach = func(a agent.Attached) { attached <- a }
	runDone := make(chan error, 1)
	go func() { runDone <- rn.Run(ctx) }()
	select {
	case a := <-attached:
		t.Fatalf("revoked key attached: lease %s", a.LeaseID)
	case <-ctx.Done():
	}
	select {
	case <-runDone:
	default:
		t.Fatal("agent runner did not exit after terminal deny")
	}
}

type streamResult struct {
	body string
	err  error
	el   time.Duration
}

// TestRevokeTerminatesInflightStream: revoking visitor access must abort an
// in-flight protected response, not let it run to completion (C10/F07).
func TestRevokeTerminatesInflightStream(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	before := app.Hits()
	done := make(chan streamResult, 1)
	start := time.Now()
	go func() {
		resp, err := http.DefaultClient.Do(slowReq(t, h, cookie))
		if err != nil {
			done <- streamResult{err: err, el: time.Since(start)}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		done <- streamResult{body: string(body), err: err, el: time.Since(start)}
	}()

	// Wait until the request has reached the local app, then revoke.
	deadline := time.Now().Add(10 * time.Second)
	for app.Hits() == before {
		if time.Now().After(deadline) {
			t.Fatal("slow request never reached the local app")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "revoke"); code != http.StatusOK {
		t.Fatalf("revoke: want 200 got %d", code)
	}
	select {
	case r := <-done:
		if r.body == "slow done" || r.el >= 4500*time.Millisecond {
			t.Fatalf("revoked stream ran to completion: body=%q elapsed=%v err=%v", r.body, r.el, r.err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("revoked stream never terminated")
	}
}

func slowReq(t *testing.T, h *harness, cookie string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", h.relaySrv.URL+"/slow", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = h.host()
	req.Header.Set("Cookie", cookie)
	return req
}

// TestRevokeTerminatesWebSocket: a pre-revoke WebSocket must close promptly
// after revoke, not live out its 6h lifetime (C10/F07/G04).
func TestRevokeTerminatesWebSocket(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	conn := wsDial(t, h, cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatalf("pre-revoke echo write: %v", err)
	}
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("pre-revoke echo read: %v", err)
	}
	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "revoke"); code != http.StatusOK {
		t.Fatalf("revoke: want 200 got %d", code)
	}
	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel2()
	if _, _, err := conn.Read(ctx2); err == nil {
		t.Fatal("websocket survived revoke")
	} else if el := time.Since(start); el >= 5*time.Second {
		t.Fatalf("websocket outlived revoke: closed only after %v (timeout-shaped)", el)
	}
	conn.Close(websocket.StatusNormalClosure, "")
}

// TestTTLExpiryAbortsInflight: a response still streaming when the TTL
// lapses must abort, not run to completion (R4).
func TestTTLExpiryAbortsInflight(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{TTLSeconds: 2})
	cookie := redeem(t, h)

	done := make(chan streamResult, 1)
	start := time.Now()
	go func() {
		resp, err := http.DefaultClient.Do(slowReq(t, h, cookie))
		if err != nil {
			done <- streamResult{err: err, el: time.Since(start)}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		done <- streamResult{body: string(body), err: err, el: time.Since(start)}
	}()
	select {
	case r := <-done:
		// TTL is 2s, /slow needs 5s: the stream must die at expiry.
		// (Observed: 404 "lease expired" at ~2.0s.)
		if r.body == "slow done" || r.el >= 4500*time.Millisecond {
			t.Fatalf("post-expiry stream ran to completion: body=%q elapsed=%v err=%v", r.body, r.el, r.err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("expired stream never terminated")
	}
}

// TestWSMaxLifetimeEnforced: an idle-but-open WebSocket must still die at
// the max lifetime instead of living forever (G04).
func TestWSMaxLifetimeEnforced(t *testing.T) {
	old := relay.WSMaxLifetime
	relay.WSMaxLifetime = 2 * time.Second
	defer func() { relay.WSMaxLifetime = old }()

	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	conn := wsDial(t, h, cookie)
	defer conn.Close(websocket.StatusNormalClosure, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	// Idle from here: read deadlines refresh, but the lifetime timer must
	// still fire at 2s.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	start := time.Now()
	if _, _, err := conn.Read(ctx2); err == nil {
		t.Fatal("websocket survived max lifetime")
	} else if el := time.Since(start); el >= 8*time.Second {
		t.Fatalf("websocket outlived max lifetime: %v", el)
	}
	_ = limits.WSIdleTimeout // documented relationship, not a magic number
}

// TestLeaseStatusReflectsRouteLiveness: the signed status endpoint
// reports whether a session is actually forwarding (route_live), not just
// that the lease row exists. Attached shows a live route at the attached
// generation; after the agent goes away the route reads down while the
// lease itself is untouched.
func TestLeaseStatusReflectsRouteLiveness(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	statusOf := func() map[string]any {
		t.Helper()
		code, raw := h.mgmt(t, h.agentKey, h.keyID, "GET", "status")
		if code != http.StatusOK {
			t.Fatalf("status code %d", code)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("status decode: %v", err)
		}
		return got
	}
	got := statusOf()
	if got["route_live"] != true {
		t.Fatalf("attached status route_live = %v, want true", got["route_live"])
	}
	if g, ok := got["live_generation"].(float64); !ok || uint64(g) != h.attached.Generation {
		t.Fatalf("live_generation = %v, want %d", got["live_generation"], h.attached.Generation)
	}
	// Agent goes away: the lease row survives (reconnect grace) but no
	// session forwards.
	h.cancel()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got = statusOf()
		if got["route_live"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("route still live after agent shutdown: %v", got)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestLeaseStatusReflectsAuthoritativeState: the signed status endpoint
// reports the live lease state (ACTIVE, then REVOKED after revoke), so
// `ocliv status` can show authoritative state instead of a stale cache.
func TestLeaseStatusReflectsAuthoritativeState(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	statusOf := func() map[string]any {
		t.Helper()
		code, raw := h.mgmt(t, h.agentKey, h.keyID, "GET", "status")
		if code != http.StatusOK {
			t.Fatalf("status code %d", code)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("status decode: %v", err)
		}
		return got
	}
	if got := statusOf(); got["status"] != "ACTIVE" || got["lease_id"] != h.attached.LeaseID {
		t.Fatalf("attached status = %v", got)
	}
	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "revoke"); code != http.StatusOK {
		t.Fatalf("revoke status %d", code)
	}
	if got := statusOf(); got["status"] != "REVOKED" {
		t.Fatalf("revoked status = %v", got)
	}
}
