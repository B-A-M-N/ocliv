package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	"ocliv/internal/transport"
)

// connectWithIntent performs a raw agent handshake with a caller-built
// intent payload and reports whether the relay attached a session.
func connectWithIntent(t *testing.T, h *harness, intent map[string]any) bool {
	t.Helper()
	chBody, _ := json.Marshal(map[string]string{"key_id": h.keyID})
	resp, err := h.enrollClient().Post(h.relaySrv.URL+"/v1/agent/challenge", "application/json", bytes.NewReader(chBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ch struct {
		Nonce   string `json:"nonce"`
		Origin  string `json:"origin"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&ch); err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	intentRaw, _ := json.Marshal(intent)
	ts := time.Now().UTC()
	sig := h.agentKey.Sign(nonce, ch.Origin, ch.Version, ts, string(intentRaw))
	header := http.Header{
		"X-Ocliv-Key":    []string{h.keyID},
		"X-Ocliv-Nonce":  []string{ch.Nonce},
		"X-Ocliv-Ts":     []string{ts.Format(time.RFC3339Nano)},
		"X-Ocliv-Intent": []string{base64.StdEncoding.EncodeToString(intentRaw)},
		"X-Ocliv-Sig":    []string{base64.StdEncoding.EncodeToString(sig)},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws://"+h.relaySrv.Listener.Addr().String()+"/v1/agent/connect",
		&websocket.DialOptions{HTTPHeader: header, CompressionMode: websocket.CompressionDisabled,
			HTTPClient: &http.Client{Transport: h.handshakeTransport()}})
	if err != nil {
		return false
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	// The handshake completes only with an attached message; post-accept
	// denials close without one, which Dial alone cannot distinguish.
	readCtx, readCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer readCancel()
	raw, err := transport.ReadControl(readCtx, conn)
	if err != nil {
		return false
	}
	var att struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &att); err != nil {
		return false
	}
	return att.Type == "attached"
}

// TestUnknownResumeIDCannotBypassReadiness: an unknown, nonempty resume
// ID with unconfirmed readiness must not fall through to a fresh
// allocation. The Ready gate applies whenever a new lease would be
// created, not only when no resume was attempted (F06, P0-3).
func TestUnknownResumeIDCannotBypassReadiness(t *testing.T) {
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()

	countLeases := func() int {
		var n int
		if err := h.db.SQL().QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	badIntents := []map[string]any{
		{"port": 3000, "version": "ocliv/1", "lease_id": "lse-unknown-1", "ready": false},
		{"port": 3000, "version": "ocliv/1", "lease_id": "lse-unknown-2"},
	}
	for i, intent := range badIntents {
		if connectWithIntent(t, h, intent) {
			t.Fatalf("intent %d attached without confirmed readiness", i)
		}
		if got := countLeases(); got != 0 {
			t.Fatalf("intent %d allocated %d lease rows", i, got)
		}
	}
}

// TestOversizedTTLRejected: a TTL that cannot be represented as a
// time.Duration must be rejected, not silently wrapped into a wrong
// expiry window.
func TestOversizedTTLRejected(t *testing.T) {
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()

	intent := map[string]any{"port": 3000, "version": "ocliv/1", "ready": true, "ttl_seconds": int64(1) << 62}
	if connectWithIntent(t, h, intent) {
		t.Fatal("oversized TTL attached")
	}
	// Positive control: a sane TTL still attaches.
	good := map[string]any{"port": 3000, "version": "ocliv/1", "ready": true, "ttl_seconds": 3600}
	if !connectWithIntent(t, h, good) {
		t.Fatal("bounded TTL rejected")
	}
}

// TestHandshakeVersionEnforced: an intent without (or with a wrong)
// protocol version must be rejected, not attached (B10).
func TestHandshakeVersionEnforced(t *testing.T) {
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()

	badIntents := []map[string]any{
		{"port": 3000, "ready": true},                                          // missing version
		{"port": 3000, "ready": true, "version": "ocliv/0"},                    // wrong version
		{"port": 3000, "ready": true, "version": "ocliv/1", "ttl_seconds": -5}, // bad ttl, valid version
		{"port": 3000, "version": "ocliv/1"},                                   // readiness not confirmed
	}
	for i, intent := range badIntents {
		if connectWithIntent(t, h, intent) {
			t.Fatalf("intent %d attached without valid version negotiation", i)
		}
	}
	// Positive control: a fully valid intent attaches.
	good := map[string]any{"port": 3000, "ready": true, "version": "ocliv/1"}
	if !connectWithIntent(t, h, good) {
		t.Fatal("valid intent rejected")
	}
}
