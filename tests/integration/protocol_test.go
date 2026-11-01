package integration

import (
	"io"
	"net/http"
	"testing"
)

// TestSetCookiePreserved: multiple Set-Cookie headers must arrive as
// separate cookie lines, not one merged line (E04/E09).
func TestSetCookiePreserved(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	resp := h.visitorReq(t, "GET", "/multicookie", nil, authedHeaders(cookie))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("multicookie: status=%d", resp.StatusCode)
	}
	var got []string
	for _, c := range resp.Cookies() {
		got = append(got, c.Name+"="+c.Value)
	}
	if len(got) != 2 {
		t.Fatalf("Set-Cookie lines lost: cookies=%q raw=%q", got, resp.Header.Values("Set-Cookie"))
	}
}

// TestNonWSUpgradeRejected: an Upgrade that is not a valid WebSocket
// handshake must fail closed, never downgrade to plain HTTP (E01/D11).
func TestNonWSUpgradeRejected(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	before := app.Hits()
	resp := h.visitorReq(t, "GET", "/", nil, map[string]string{
		"Cookie":     cookie,
		"Upgrade":    "h2c",
		"Connection": "Upgrade",
	})
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-WS upgrade: want 400 got %d", resp.StatusCode)
	}
	if got := app.Hits() - before; got != 0 {
		t.Fatalf("rejected upgrade reached local app %d times", got)
	}
}

// TestTrailersRejected: trailers cannot be delivered intact (headers are
// already committed upstream), so a trailered response must be aborted,
// never silently completed as if whole (E12).
func TestTrailersRejected(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	cookie := redeem(t, h)

	resp := h.visitorReq(t, "GET", "/trailers", nil, authedHeaders(cookie))
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	// The agent aborts announced-trailer responses before committing, so
	// the relay cannot deliver a body it can never complete: 502.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("trailered response: want 502 got %d body=%q", resp.StatusCode, body)
	}
}
