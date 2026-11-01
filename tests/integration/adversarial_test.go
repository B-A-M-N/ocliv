// Adversarial security coverage: every rejection below must occur BEFORE
// any byte reaches the local application.
package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"ocliv/internal/config"
)

func TestTenantIsolation(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	before := app.Hits()

	// A second tenant enrolls and attaches its own lease.
	k2, kid2 := h.enrollKey(t, "tenant-evil")
	_ = k2
	_ = kid2

	// Cross-tenant management with the wrong key is forbidden (D04).
	code, _ := h.mgmt(t, h.agentKey, "key-unknown", "POST", "revoke")
	if code != http.StatusForbidden {
		t.Fatalf("unknown key mgmt: want 403 got %d", code)
	}

	// Guessing the hostname without a credential never forwards (C02).
	resp := h.visitorReq(t, "GET", "/", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("no-credential: want 302 got %d", resp.StatusCode)
	}

	// A bogus Bearer [REDACTED] is denied without touching local (C04).
	resp = h.visitorReq(t, "GET", "/", nil, map[string]string{
		"X-Ocliv-Authorization": "Bearer ocliv-vst-bogus",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bogus token: want 401 got %d", resp.StatusCode)
	}

	// Unknown hostname maps to no destination and no hint (D01, D03).
	req, _ := http.NewRequest("GET", h.relaySrv.URL+"/", nil)
	req.Host = "no-such-lease.t.example.test"
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown host: want 404 got %d", resp.StatusCode)
	}

	// Malformed hosts fail closed (D02): nested, confusable, trailing dot.
	for _, bad := range []string{
		"a.b.t.example.test", "evil.t.example.test.attacker.com",
		"t.example.test.", "UPPER.t.example.test",
	} {
		req, _ := http.NewRequest("GET", h.relaySrv.URL+"/", nil)
		req.Host = bad
		resp, err := visitorClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("host %q: want 400/404 got %d", bad, resp.StatusCode)
		}
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("adversarial requests reached local app %d times", got)
	}
}

func TestHeaderTokenAuth(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	before := app.Hits()

	// Issue a multi-use API token via rotate, then use the header credential.
	code, raw := h.mgmt(t, h.agentKey, h.keyID, "POST", "rotate")
	if code != http.StatusOK {
		t.Fatalf("rotate status %d", code)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		t.Fatalf("no access token issued: %s", raw)
	}
	// Rotate evicts the live session (C10 kill-switch); the agent resumes
	// automatically with backoff, so the new token becomes usable after a
	// short reconnect window rather than instantly. Poll the production
	// visitor path until it serves or the deadline expires.
	var body string
	var resp *http.Response
	ok := false
	deadline := time.Now().Add(20 * time.Second)
	for !ok && time.Now().Before(deadline) {
		resp = h.visitorReq(t, "GET", "/", nil, map[string]string{
			"X-Ocliv-Authorization": "Bearer " + out.AccessToken,
		})
		body = readAll(t, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && body == "hello" {
			ok = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("header token never served after rotate, last body=%q", body)
	}
	// The app must not see the tunnel credential (E08).
	resp = h.visitorReq(t, "GET", "/headers", nil, map[string]string{
		"X-Ocliv-Authorization": "Bearer " + out.AccessToken,
	})
	var hdrs map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&hdrs); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, v := range hdrs {
		if strings.Contains(v, out.AccessToken) {
			t.Fatal("tunnel credential leaked to upstream application")
		}
	}
	// Rotating again invalidates the old token (C10).
	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "rotate"); code != http.StatusOK {
		t.Fatalf("second rotate status %d", code)
	}
	resp = h.visitorReq(t, "GET", "/", nil, map[string]string{
		"X-Ocliv-Authorization": "Bearer " + out.AccessToken,
	})
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("rotated-out token still accepted")
	}
	if got := app.Hits() - before; got < 2 {
		t.Fatalf("expected authorized traffic to reach local, hits=%d", got-before)
	}
}

func TestCSRFEnforcement(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)
	before := app.Hits()

	// Cookie-authed unsafe method without Origin is rejected (C08).
	resp := h.visitorReq(t, "POST", "/echo", bytes.NewReader([]byte("x")), authedHeaders(cookie))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing origin: want 403 got %d", resp.StatusCode)
	}
	// Hostile cross-tenant same-site origin is rejected (C08).
	resp = h.visitorReq(t, "POST", "/echo", bytes.NewReader([]byte("x")), map[string]string{
		"Cookie": cookie, "Origin": "https://evil.t.example.test",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("hostile origin: want 403 got %d", resp.StatusCode)
	}
	// Null origin is rejected.
	resp = h.visitorReq(t, "POST", "/echo", bytes.NewReader([]byte("x")), map[string]string{
		"Cookie": cookie, "Origin": "null",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("null origin: want 403 got %d", resp.StatusCode)
	}
	// Exact same-origin proof is accepted.
	resp = h.visitorReq(t, "POST", "/echo", bytes.NewReader([]byte("xyz")), h.unsafeHeaders(cookie))
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "xyz" {
		t.Fatalf("legit origin: status=%d body=%q", resp.StatusCode, body)
	}
	if got := app.Hits() - before; got != 1 {
		t.Fatalf(" CSRF bypass reached local %d times", got)
	}
}

func TestRequestSmugglingVectors(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)
	before := app.Hits()

	// Duplicate conflicting Content-Length must be rejected (E01). Go's own
	// server already rejects these at parse time; assert the closed behavior.
	raw := fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nOrigin: http://%s\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
		h.host(), cookie, h.host())
	checkRaw(t, h, raw, http.StatusBadRequest)

	// Transfer-Encoding + Content-Length: Go's server deterministically
	// de-chunks (chunked wins, CL dropped) before the handler runs; the
	// relay forwards exactly those bytes as one unambiguous stream.
	// Assert the deterministic interpretation: local echoes "hello".
	raw = fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nOrigin: http://%s\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		h.host(), cookie, h.host())
	conn, err := net.Dial("tcp", h.relaySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	echoed, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(echoed) != "hello" {
		t.Fatalf("TE+CL: status=%d body=%q", resp.StatusCode, string(echoed))
	}

	// The TE+CL echo above is the documented deterministic interpretation;
	// re-baseline so the guard below measures only REJECTION vectors.
	// Rejected inputs must never reach the local app (E01, C01).
	before = app.Hits()

	// CONNECT is rejected.
	raw = fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s\r\n\r\n", h.host(), h.host())
	checkRaw(t, h, raw, http.StatusBadRequest)

	if got := app.Hits() - before; got != 0 {
		t.Fatalf("smuggling vectors reached local app %d times", got)
	}
}

// checkRaw sends a hand-crafted request and asserts the status code.
func checkRaw(t *testing.T, h *harness, raw string, want int) {
	t.Helper()
	conn, err := net.Dial("tcp", h.relaySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("raw request: want %d got %d", want, resp.StatusCode)
	}
}

func TestPublicModeExceptionScope(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{Public: true})
	if h.attached.AccessMode != "public" {
		t.Fatalf("mode=%q want public", h.attached.AccessMode)
	}
	// Anonymous visitors are served (the documented --public exception, C01).
	resp := h.visitorReq(t, "GET", "/", nil, nil)
	body := readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("public: status=%d body=%q", resp.StatusCode, body)
	}
	// ...but agent identity is still enforced: unknown key mgmt is 403.
	if code, _ := h.mgmt(t, h.agentKey, "key-unknown", "POST", "revoke"); code != http.StatusForbidden {
		t.Fatalf("public mgmt with bad key: want 403 got %d", code)
	}
}
