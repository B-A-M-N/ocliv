// Chaos-coverage gaps: network partition, mid-stream reconnect, conflicting
// mutations, restart with unfinished work. Each test asserts the SAFE
// deterministic outcome. If the code cannot guarantee an outcome, the strict
// assertion stays and the failure is the finding.
package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

// partitionLink is a transparent TCP forward proxy between the agent and
// the relay listener. sever() drops every bridged connection and refuses
// new ones while BOTH processes stay alive; heal() lets the agent's own
// reconnect loop resume through the same proxy. This severs only the
// agent-relay link: neither side is killed and no listener is closed.
type partitionLink struct {
	relayAddr string
	ln        net.Listener
	mu        sync.Mutex
	cut       bool
	live      map[net.Conn]struct{}
}

func newPartitionLink(t *testing.T, relayAddr string) *partitionLink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &partitionLink{relayAddr: relayAddr, ln: ln, live: map[net.Conn]struct{}{}}
	go p.serve()
	t.Cleanup(p.shutdown)
	return p
}

func (p *partitionLink) serve() {
	for {
		in, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.bridge(in)
	}
}

func (p *partitionLink) bridge(in net.Conn) {
	p.mu.Lock()
	if p.cut {
		p.mu.Unlock()
		in.Close()
		return
	}
	out, err := net.DialTimeout("tcp", p.relayAddr, 10*time.Second)
	if err != nil {
		p.mu.Unlock()
		in.Close()
		return
	}
	p.live[in] = struct{}{}
	p.live[out] = struct{}{}
	p.mu.Unlock()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, in); done <- struct{}{} }()
	go func() { _, _ = io.Copy(in, out); done <- struct{}{} }()
	<-done
	p.mu.Lock()
	delete(p.live, in)
	delete(p.live, out)
	p.mu.Unlock()
	in.Close()
	out.Close()
	<-done
}

func (p *partitionLink) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	p.mu.Lock()
	cut := p.cut
	p.mu.Unlock()
	if cut {
		return nil, fmt.Errorf("partitionLink: link cut")
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", p.ln.Addr().String())
}

// agentTransport routes the agent handshake (challenge POST + WSS dial)
// through the proxy while still presenting the relay authority, exactly
// like the harness handshake transport does over loopback.
func (p *partitionLink) agentTransport(relayHost string) http.RoundTripper {
	base := &http.Transport{DialContext: p.dialContext}
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		r2 := req.Clone(req.Context())
		r2.Host = relayHost
		return base.RoundTrip(r2)
	})
}

func (p *partitionLink) sever() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cut = true
	for c := range p.live {
		c.Close()
	}
	p.live = map[net.Conn]struct{}{}
}

func (p *partitionLink) heal() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cut = false
}

func (p *partitionLink) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cut = true
	for c := range p.live {
		c.Close()
	}
	p.ln.Close()
}

// gapRouteLive reports the signed status endpoint's route liveness view.
func gapRouteLive(t *testing.T, h *harness) (bool, uint64) {
	t.Helper()
	code, raw := h.mgmt(t, h.agentKey, h.keyID, "GET", "status")
	if code != http.StatusOK {
		t.Fatalf("status code %d", code)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("status decode: %v", err)
	}
	live, _ := got["route_live"].(bool)
	var gen uint64
	if f, ok := got["live_generation"].(float64); ok {
		gen = uint64(f)
	}
	return live, gen
}

// tryShareURL mints one share token without touching *testing.T, so storm
// goroutines never call FailNow off the test goroutine.
func tryShareURL(h *harness) (string, bool) {
	ts := time.Now().UTC()
	path := "/v1/agent/lease/" + h.attached.LeaseID + "/share"
	nonce, err := agent.MgmtNonce()
	if err != nil {
		return "", false
	}
	sig := ed25519.Sign(h.agentKey.Private(), agent.MgmtMessage(h.keyID, "POST", path, ts, nonce))
	req, err := http.NewRequest("POST", h.relaySrv.URL+path, nil)
	if err != nil {
		return "", false
	}
	req.Host = h.relayHost
	req.Header.Set("X-Ocliv-Key", h.keyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	resp, err := visitorClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil || m["share_url"] == "" {
		return "", false
	}
	return m["share_url"], true
}

// racedTokenGrantsNothing proves a share URL minted during a revoke storm
// authorizes no traffic afterwards: either it no longer redeems, or the
// redeemed credential is still denied at the route.
func racedTokenGrantsNothing(t *testing.T, h *harness, shareURL string) {
	t.Helper()
	parts := strings.SplitN(shareURL, "#t=", 2)
	if len(parts) != 2 || parts[1] == "" {
		t.Fatalf("minted share_url has no token: %q", shareURL)
	}
	body, _ := json.Marshal(map[string]string{"token": parts[1]})
	req, err := http.NewRequest("POST", h.relaySrv.URL+"/_ocliv/redeem", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = h.host()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+h.host())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return // unreachable: grants nothing
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return // revoked token no longer redeems: grants nothing
	}
	var ck string
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-ocliv-visitor" {
			ck = c.Name + "=" + c.Value
		}
	}
	if ck == "" {
		return
	}
	r := h.visitorReq(t, "GET", "/", nil, authedHeaders(ck))
	r.Body.Close()
	if r.StatusCode == http.StatusOK {
		t.Fatalf("share minted during revoke storm still serves traffic")
	}
}

// A. Network partition: sever only the agent-relay link while both processes
// stay alive. Visitor traffic must degrade to 503 with no false 200 and
// never reach the app; after heal the same lease resumes (fenced gen+1)
// with no duplicated side effects.
func TestNetworkPartitionDegradesAndRecoversSafely(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()

	link := newPartitionLink(t, h.relaySrv.Listener.Addr().String())

	agentDir, err := os.MkdirTemp("", "ocliv-agent-part-*")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attached := make(chan agent.Attached, 8)
	rn := &agent.Runner{
		Cfg:                config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port, DataDir: agentDir},
		Key:                h.agentKey,
		KeyID:              h.keyID,
		Target:             fmt.Sprintf("127.0.0.1:%d", app.Port),
		HandshakeTransport: link.agentTransport(h.relayHost),
		OnAttach:           func(a agent.Attached) { h.attached = a; attached <- a },
	}
	go func() { _ = rn.Run(ctx) }()
	var first agent.Attached
	select {
	case first = <-attached:
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not attach through partition link")
	}
	leaseID, hostname, gen0 := first.LeaseID, first.Hostname, first.Generation
	cookie := redeem(t, h)

	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("pre-partition: status=%d body=%q", resp.StatusCode, body)
	}

	// Sever ONLY the link. Both processes keep running.
	link.sever()

	// Degradation must be deterministic: never a false 200; converge to a
	// steady 503 (a brief non-200 transient during dead-session detection
	// is acceptable, success is not).
	consec := 0
	deadline := time.Now().Add(30 * time.Second)
	for consec < 3 {
		if time.Now().After(deadline) {
			t.Fatal("partition never converged to steady 503")
		}
		r := h.visitorReq(t, "POST", "/echo", strings.NewReader("partition-probe"), h.unsafeHeaders(cookie))
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Fatal("false 200 during partition: severed lease served traffic")
		}
		if r.StatusCode == http.StatusServiceUnavailable {
			consec++
		} else {
			consec = 0
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Partition-window traffic must never reach the local app. The
	// baseline is taken AFTER steady 503, so pre-detection races cannot
	// pollute the accounting; agent readiness probes are GET and never
	// touch the POST counter.
	p0 := app.postHits.Load()
	for i := 0; i < 3; i++ {
		r := h.visitorReq(t, "POST", "/echo", strings.NewReader("partition-probe"), h.unsafeHeaders(cookie))
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("steady partition: want 503 got %d", r.StatusCode)
		}
	}
	if got := app.postHits.Load(); got != p0 {
		t.Fatalf("partitioned traffic reached the app %d times", got-p0)
	}

	// Heal: the SAME agent process resumes by itself through the link.
	link.heal()
	var resumed agent.Attached
	select {
	case resumed = <-attached:
	case <-time.After(45 * time.Second):
		t.Fatal("agent did not resume after heal")
	}
	if resumed.LeaseID != leaseID {
		t.Fatalf("resume changed lease: %q -> %q", leaseID, resumed.LeaseID)
	}
	if resumed.Hostname != hostname {
		t.Fatalf("resume changed hostname: %q -> %q", hostname, resumed.Hostname)
	}
	if resumed.Generation != gen0+1 {
		t.Fatalf("resume generation=%d want %d", resumed.Generation, gen0+1)
	}
	var st string
	if err := h.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "ACTIVE" {
		t.Fatalf("post-heal status %q, want ACTIVE", st)
	}
	// The relay never restarted, so the original cookie still authorizes.
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	body = readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("post-heal: status=%d body=%q", resp.StatusCode, body)
	}
	// Exactly one new app execution: the partitioned probes were never
	// replayed after recovery.
	resp = h.visitorReq(t, "POST", "/echo", strings.NewReader("healed"), h.unsafeHeaders(cookie))
	got, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(got) != "healed" {
		t.Fatalf("post-heal echo: status=%d body=%q", resp.StatusCode, got)
	}
	if d := app.postHits.Load() - p0; d != 1 {
		t.Fatalf("post-heal app executions=%d want exactly 1 (replay?)", d)
	}
}

// B. Reconnect during an active stream: drop the agent session mid-stream.
// The orphaned stream must abort with a read error, never clean completion,
// and a follow-up on the resumed lease must succeed.
func TestReconnectDuringActiveStreamAbortsOrphan(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)
	leaseID, gen0 := h.attached.LeaseID, h.attached.Generation

	// /slow-body commits the head immediately then stalls the body 4s, so
	// cancelling mid-stall orphans a committed stream.
	type streamOut struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan streamOut, 1)
	before := app.postHits.Load()
	go func() {
		req, _ := http.NewRequest("POST", h.relaySrv.URL+"/slow-body", nil)
		req.Host = h.host()
		for k, v := range h.unsafeHeaders(cookie) {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- streamOut{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		done <- streamOut{status: resp.StatusCode, body: b, err: err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for app.postHits.Load() < before+1 {
		if time.Now().After(deadline) {
			t.Fatal("slow-body never reached the app")
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // head committed, body stalled
	h.cancel()                         // drop the agent session mid-stream
	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("orphaned stream completed cleanly: status=%d bytes=%d", r.status, len(r.body))
		}
		if string(r.body) == "late body" {
			t.Fatalf("orphaned stream delivered the full late body with err=%v", r.err)
		}
		t.Logf("orphan aborted as required: status=%d bytes=%d err=%v", r.status, len(r.body), r.err)
	case <-time.After(20 * time.Second):
		t.Fatal("orphaned stream never terminated")
	}
	// A fresh image resumes the same lease; the follow-up succeeds.
	h.restartAgent(t, app.Port)
	if h.attached.LeaseID != leaseID {
		t.Fatalf("resume changed lease: %q -> %q", leaseID, h.attached.LeaseID)
	}
	if h.attached.Generation != gen0+1 {
		t.Fatalf("resume generation=%d want %d", h.attached.Generation, gen0+1)
	}
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("post-resume: status=%d body=%q", resp.StatusCode, body)
	}
}

// C1. Revoke against concurrent share storm: the terminal state must win.
// No raced share may authorize traffic afterwards, and no live session may
// remain registered.
func TestRevokeWinsOverConcurrentShareStorm(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)
	leaseID, gen0 := h.attached.LeaseID, h.attached.Generation

	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke status %d", resp.StatusCode)
	}

	var mu sync.Mutex
	var urls []string
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if u, ok := tryShareURL(h); ok {
					mu.Lock()
					urls = append(urls, u)
					mu.Unlock()
				}
			}
		}()
	}
	for i := 0; i < 60; i++ {
		if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "revoke"); code != http.StatusOK {
			close(stop)
			wg.Wait()
			t.Fatalf("revoke %d: status %d", i, code)
		}
	}
	close(stop)
	wg.Wait()

	var status string
	var gen int64
	var n int
	if err := h.db.SQL().QueryRow(`SELECT status, generation FROM leases WHERE id=?`, leaseID).Scan(&status, &gen); err != nil {
		t.Fatal(err)
	}
	if err := h.db.SQL().QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if status != "REVOKED" {
		t.Fatalf("terminal state lost: status %q", status)
	}
	if n != 1 {
		t.Fatalf("revoke storm minted replacements: count=%d", n)
	}
	if gen != int64(gen0) {
		t.Fatalf("generation moved on terminal lease: %d -> %d", gen0, gen)
	}
	live, _ := gapRouteLive(t, h)
	if live {
		t.Fatal("live session still registered after revoke")
	}
	time.Sleep(2 * time.Second) // sustained terminal: no resurrection
	if live, _ := gapRouteLive(t, h); live {
		t.Fatal("session resurrected after revoke")
	}
	var st2 string
	if err := h.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&st2); err != nil {
		t.Fatal(err)
	}
	if st2 != "REVOKED" {
		t.Fatalf("lease resurrected to %q", st2)
	}
	before := app.Hits()
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("revoked credential still serves traffic")
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("revoked lease reached the app %d times", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for i, u := range urls {
		if i >= 3 {
			break
		}
		racedTokenGrantsNothing(t, h, u)
	}
}

// C2. Close against a resume storm: the terminal state must win with no
// live session left registered and no traffic served afterwards.
func TestCloseTerminalAgainstResumeStorm(t *testing.T) {
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
	var n int
	if err := h.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := h.db.SQL().QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if status != "CLOSED" {
		t.Fatalf("terminal state lost: status %q", status)
	}
	if n != 1 {
		t.Fatalf("close storm minted replacements: count=%d", n)
	}
	if live, _ := gapRouteLive(t, h); live {
		t.Fatal("live session still registered after close")
	}
	time.Sleep(2 * time.Second) // sustained terminal: no resurrection
	var st2 string
	if err := h.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&st2); err != nil {
		t.Fatal(err)
	}
	if st2 != "CLOSED" {
		t.Fatalf("lease resurrected to %q", st2)
	}
	if live, _ := gapRouteLive(t, h); live {
		t.Fatal("session resurrected after close")
	}
	before := app.Hits()
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("traffic served after close")
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("closed lease reached the app %d times", got)
	}
}

// D. Restart with unfinished work: hold an in-flight stream across a relay
// restart on a raw connection (no client retries can mask the outcome).
// The pre-restart stream must never report clean completion, and the
// post-restart resume must be generation-fenced on the same lease with no
// replay of the in-flight request.
func TestRestartWithUnfinishedWorkFencesResume(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)
	leaseID := h.attached.LeaseID
	hostname := h.attached.Hostname
	before := app.postHits.Load()

	// Raw TCP: /slow needs 5s, so killing the relay in milliseconds
	// guarantees the head could never commit before death.
	relayAddr := h.relaySrv.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", relayAddr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Cookie-authed POSTs require the same-origin proof browsers attach
	// (C08): without Origin the relay denies before forwarding.
	_, _ = fmt.Fprintf(conn, "POST /slow HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nOrigin: http://%s\r\n"+
		"Content-Length: 5\r\nConnection: close\r\n\r\nhello", h.host(), cookie, h.host())
	deadline := time.Now().Add(10 * time.Second)
	for app.postHits.Load() < before+1 {
		if time.Now().After(deadline) {
			conn.Close()
			t.Fatal("in-flight request never reached the app")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Crash the relay mid-flight and rebuild it over the same DB and port.
	// Close alone would gracefully drain the in-flight stream (it blocks
	// until outstanding requests complete); CloseClientConnections is the
	// abrupt kill: every socket dies now, like SIGKILL, so unfinished
	// work cannot drain to completion.
	h.relaySrv.CloseClientConnections()
	// Stop the orphaned agent image before rebuilding: its reconnect loop
	// would otherwise race the fresh image for the fenced resume.
	h.cancel()
	h.relaySrv.Close()
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
	h.restartAgent(t, app.Port)

	// The orphaned stream must never report clean completion.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	raw, readErr := io.ReadAll(conn)
	conn.Close()
	t.Logf("orphaned stream across restart: bytes=%d readErr=%v", len(raw), readErr)
	if strings.Contains(string(raw), "slow done") {
		t.Fatalf("pre-restart stream reported clean completion across relay restart")
	}
	if len(raw) != 0 {
		// The relay died before the 5s app could answer: any bytes at
		// all would be fabricated, not forwarded.
		t.Fatalf("pre-restart stream delivered %d bytes across relay death: %q", len(raw), string(raw))
	}

	// Post-restart resume is fenced: same lease, same host, gen 2, one row.
	var gen int64
	var st string
	_ = db2.SQL().QueryRow(`SELECT generation, status FROM leases WHERE id=?`, leaseID).Scan(&gen, &st)
	if st != "ACTIVE" || gen != 2 {
		t.Fatalf("agent did not resume fenced (gen=%d status=%q)", gen, st)
	}
	if h.attached.LeaseID != leaseID || h.attached.Hostname != hostname {
		t.Fatalf("resume changed identity: %+v", h.attached)
	}
	var count int
	_ = h.db.SQL().QueryRow(`SELECT COUNT(*) FROM leases WHERE id=? AND generation=2`, leaseID).Scan(&count)
	if count != 1 {
		t.Fatal("fencing did not advance generation atomically")
	}
	// Old cookie fail-closes; a fresh share resumes traffic on the URL.
	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusFound {
		t.Fatalf("pre-restart cookie after restart: want denial, got %d", resp.StatusCode)
	}
	code, shr := h.mgmt(t, h.agentKey, h.keyID, "POST", "share")
	if code != http.StatusOK {
		t.Fatalf("post-restart share: want 200 got %d (%s)", code, shr)
	}
	var m map[string]string
	if err := json.Unmarshal(shr, &m); err != nil || m["share_url"] == "" {
		t.Fatalf("post-restart share returned no share_url: %v", err)
	}
	fresh := redeemURL(t, h, m["share_url"])
	resp = h.visitorReq(t, "GET", "/", nil, authedHeaders(fresh))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("post-restart: status=%d body=%q", resp.StatusCode, body)
	}
	// The in-flight request executed exactly once: resume never replayed it.
	if got := app.postHits.Load(); got != before+1 {
		t.Fatalf("in-flight request executed %d times, want exactly 1", got-before)
	}

}

// H1. Compound: revoke DURING a network partition, then heal. The terminal
// revocation must win across the partition boundary: after heal there is no
// resurrection (no re-attach serves traffic), the lease stays REVOKED, the
// old cookie is denied, and heal-window probes never reach the app. This
// pairs class B (partition) with class G revocation-terminality while the
// agent's own reconnect loop is live.
func TestRevokeDuringPartitionStaysTerminalAfterHeal(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()

	link := newPartitionLink(t, h.relaySrv.Listener.Addr().String())

	agentDir, err := os.MkdirTemp("", "ocliv-agent-revpart-*")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attached := make(chan agent.Attached, 8)
	rn := &agent.Runner{
		Cfg:                config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port, DataDir: agentDir},
		Key:                h.agentKey,
		KeyID:              h.keyID,
		Target:             fmt.Sprintf("127.0.0.1:%d", app.Port),
		HandshakeTransport: link.agentTransport(h.relayHost),
		OnAttach:           func(a agent.Attached) { h.attached = a; attached <- a },
	}
	go func() { _ = rn.Run(ctx) }()
	var first agent.Attached
	select {
	case first = <-attached:
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not attach through partition link")
	}
	leaseID := first.LeaseID
	cookie := redeem(t, h)

	resp := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("pre-partition: status=%d body=%q", resp.StatusCode, body)
	}

	link.sever()
	consec := 0
	deadline := time.Now().Add(30 * time.Second)
	for consec < 3 {
		if time.Now().After(deadline) {
			t.Fatal("partition never converged to steady 503")
		}
		r := h.visitorReq(t, "POST", "/echo", strings.NewReader("revpart-probe"), h.unsafeHeaders(cookie))
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Fatal("false 200 during partition")
		}
		if r.StatusCode == http.StatusServiceUnavailable {
			consec++
		} else {
			consec = 0
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Revoke WHILE partitioned. Management is direct to the relay (never
	// through the severed agent link), exactly like an operator takedown
	// during an agent outage.
	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "revoke"); code != http.StatusOK {
		t.Fatalf("revoke during partition: want 200 got %d", code)
	}
	r := h.visitorReq(t, "GET", "/", nil, authedHeaders(cookie))
	_, _ = io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode == http.StatusOK {
		t.Fatal("revoked cookie served traffic while partitioned")
	}

	// Drain any stale attach signal, then heal: the runner's own
	// reconnect loop must NOT resurrect the revoked lease.
drain:
	for {
		select {
		case <-attached:
		default:
			break drain
		}
	}
	p0 := app.postHits.Load()
	link.heal()
	select {
	case a := <-attached:
		t.Fatalf("revoked lease resurrected after heal: lease %s gen %d", a.LeaseID, a.Generation)
	case <-time.After(20 * time.Second):
	}
	var st string
	if err := h.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "REVOKED" {
		t.Fatalf("post-heal status %q, want REVOKED", st)
	}
	if live, _ := gapRouteLive(t, h); live {
		t.Fatal("route live after revoke+heal")
	}
	for i := 0; i < 3; i++ {
		r := h.visitorReq(t, "POST", "/echo", strings.NewReader("healed-probe"), h.unsafeHeaders(cookie))
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Fatal("revoked lease served traffic after heal")
		}
	}
	if got := app.postHits.Load(); got != p0 {
		t.Fatalf("heal-window traffic reached the app %d times", got-p0)
	}
}
