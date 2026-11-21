package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ocliv/internal/identity"
	"ocliv/internal/limits"
	"ocliv/internal/store"
)

func newPairingServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	// Open rate limit so individual handler tests are not throttled.
	s.preAuth = limits.NewThrottle(1<<30, time.Minute)
	return s, db
}

func genPubKeyBase64(t *testing.T) string {
	t.Helper()
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Public())
}

func postPairRequest(t *testing.T, s *Server, pubKey, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"public_key": pubKey})
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/pair-request", bytes.NewReader(body))
	req.Host = "relay.example.test"
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestPairRequestCreatesCode proves that POST /v1/agent/pair-request with
// a valid ed25519 public key returns a pairing code and expiry.
func TestPairRequestCreatesCode(t *testing.T) {
	s, _ := newPairingServer(t)
	pub := genPubKeyBase64(t)
	rec := postPairRequest(t, s, pub, "192.0.2.10:1234")

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		PairingCode      string `json:"pairing_code"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.PairingCode == "" {
		t.Fatal("empty pairing_code")
	}
	// XXXX-XXXX-XXXX format: 4+1+4+1+4 = 14 chars
	if len(resp.PairingCode) != 14 {
		t.Fatalf("unexpected pairing code format %q (len=%d)", resp.PairingCode, len(resp.PairingCode))
	}
	if resp.ExpiresInSeconds <= 0 {
		t.Fatal("expires_in_seconds not set")
	}
}

// TestPairRequestRateLimitEnforced proves that a 6th pending request from
// the same IP within the window is rejected with 429.
func TestPairRequestRateLimitEnforced(t *testing.T) {
	s, _ := newPairingServer(t)
	ip := "192.0.2.42:9000"

	for i := 0; i < pairingRateLimit; i++ {
		pub := genPubKeyBase64(t)
		rec := postPairRequest(t, s, pub, ip)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i+1, rec.Code)
		}
	}
	// One over the limit.
	pub := genPubKeyBase64(t)
	rec := postPairRequest(t, s, pub, ip)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit: want 429, got %d: %s", rec.Code, rec.Body.String())
	}
}

// postPairStatus calls POST /v1/agent/pair-status with poll credentials.
func postPairStatus(t *testing.T, s *Server, pollID, pollSecret, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"poll_id": pollID, "poll_secret": pollSecret})
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/pair-status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "relay.example.test"
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestPairStatusPendingAfterRequest proves that immediately after a pair
// request the status endpoint returns "pending" when polled with the
// high-entropy poll_id + poll_secret credentials.
func TestPairStatusPendingAfterRequest(t *testing.T) {
	s, _ := newPairingServer(t)
	pub := genPubKeyBase64(t)
	rec := postPairRequest(t, s, pub, "192.0.2.11:1234")
	if rec.Code != http.StatusOK {
		t.Fatalf("pair-request: %d", rec.Code)
	}
	var pairResp struct {
		PairingCode string `json:"pairing_code"`
		PollID      string `json:"poll_id"`
		PollSecret  string `json:"poll_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pairResp); err != nil {
		t.Fatal(err)
	}
	if pairResp.PollID == "" || pairResp.PollSecret == "" {
		t.Fatal("pair-request: missing poll_id or poll_secret in response")
	}

	rec2 := postPairStatus(t, s, pairResp.PollID, pairResp.PollSecret, "192.0.2.11:1234")
	if rec2.Code != http.StatusOK {
		t.Fatalf("pair-status: want 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var sr struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &sr); err != nil {
		t.Fatal(err)
	}
	if sr.Status != "pending" {
		t.Fatalf("want status=pending, got %q", sr.Status)
	}
}

// TestPairStatusWrongSecretReturns404 proves the timing-oracle protection:
// a correct poll_id with a wrong poll_secret returns 404 (not 401/403).
func TestPairStatusWrongSecretReturns404(t *testing.T) {
	s, _ := newPairingServer(t)
	pub := genPubKeyBase64(t)
	rec := postPairRequest(t, s, pub, "192.0.2.50:1234")
	if rec.Code != http.StatusOK {
		t.Fatalf("pair-request: %d", rec.Code)
	}
	var pairResp struct {
		PollID     string `json:"poll_id"`
		PollSecret string `json:"poll_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pairResp); err != nil {
		t.Fatal(err)
	}
	// Use correct poll_id but wrong secret.
	rec2 := postPairStatus(t, s, pairResp.PollID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "192.0.2.50:1234")
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("wrong secret: want 404, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// TestPairApproveAndStatusApproved proves the full pairing flow:
// pair-request → relay.ApprovePairingRequest → pair-status returns "approved".
func TestPairApproveAndStatusApproved(t *testing.T) {
	s, db := newPairingServer(t)
	pub := genPubKeyBase64(t)
	rec := postPairRequest(t, s, pub, "192.0.2.20:1234")
	if rec.Code != http.StatusOK {
		t.Fatalf("pair-request: %d", rec.Code)
	}
	var pairResp struct {
		PairingCode string `json:"pairing_code"`
		PollID      string `json:"poll_id"`
		PollSecret  string `json:"poll_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pairResp); err != nil {
		t.Fatal(err)
	}
	if pairResp.PollID == "" || pairResp.PollSecret == "" {
		t.Fatal("pair-request: missing poll credentials")
	}

	// Operator approves using the display code (not the poll credentials).
	keyID, err := ApprovePairingRequest(db, pairResp.PairingCode, "home")
	if err != nil {
		t.Fatalf("ApprovePairingRequest: %v", err)
	}
	if keyID == "" {
		t.Fatal("empty keyID returned")
	}

	// Verify the key was inserted into agent_keys.
	var status string
	if err := db.SQL().QueryRow(`SELECT status FROM agent_keys WHERE id=?`, keyID).Scan(&status); err != nil {
		t.Fatalf("key not in agent_keys: %v", err)
	}
	if status != "active" {
		t.Fatalf("key status=%q, want active", status)
	}

	// Publisher polls with high-entropy credentials; should now return "approved".
	rec2 := postPairStatus(t, s, pairResp.PollID, pairResp.PollSecret, "192.0.2.20:1234")
	if rec2.Code != http.StatusOK {
		t.Fatalf("pair-status: want 200, got %d", rec2.Code)
	}
	var sr struct {
		Status   string `json:"status"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &sr); err != nil {
		t.Fatal(err)
	}
	if sr.Status != "approved" {
		t.Fatalf("want status=approved, got %q", sr.Status)
	}
	if sr.TenantID != "home" {
		t.Fatalf("want tenant_id=home, got %q", sr.TenantID)
	}
}

// TestPairApproveDoubleApproveRejected proves that approving an already-approved
// pairing request fails closed.
func TestPairApproveDoubleApproveRejected(t *testing.T) {
	s, db := newPairingServer(t)
	pub := genPubKeyBase64(t)
	rec := postPairRequest(t, s, pub, "192.0.2.30:1234")
	if rec.Code != http.StatusOK {
		t.Fatalf("pair-request: %d", rec.Code)
	}
	var pairResp struct {
		PairingCode string `json:"pairing_code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pairResp)

	if _, err := ApprovePairingRequest(db, pairResp.PairingCode, "home"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if _, err := ApprovePairingRequest(db, pairResp.PairingCode, "home"); err == nil {
		t.Fatal("expected error on double-approve, got nil")
	}
}
