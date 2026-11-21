package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/identity"
	"ocliv/internal/store"
)

func TestApprovePairingIdempotentAndTenantIsolation(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	keyID := "key-" + hex.EncodeToString(sum[:identity.KeyIDBytes])
	exp := time.Now().UTC().Add(10 * time.Minute)

	// 1. First pairing + approval in tenant-a.
	if err := db.CreatePairingRequest("p1", "1111-2222-3333", "poll-1", []byte("ver1"), pub, keyID, "127.0.0.1", exp); err != nil {
		t.Fatal(err)
	}
	gotKey, err := ApprovePairingRequest(db, "1111-2222-3333", "tenant-a")
	if err != nil || gotKey != keyID {
		t.Fatalf("first approve failed: key=%q err=%v", gotKey, err)
	}

	// 2. Second pairing for same active key in SAME tenant-a must succeed idempotently.
	if err := db.CreatePairingRequest("p2", "2222-3333-4444", "poll-2", []byte("ver2"), pub, keyID, "127.0.0.1", exp); err != nil {
		t.Fatal(err)
	}
	if _, err := ApprovePairingRequest(db, "2222-3333-4444", "tenant-a"); err != nil {
		t.Fatalf("idempotent approve for already-active key in same tenant failed: %v", err)
	}
	pr2, err := db.GetPairingRequest("2222-3333-4444")
	if err != nil || pr2.Status != "approved" || pr2.ResolvedTenantID != "tenant-a" {
		t.Fatalf("unexpected pr2 after idempotent approve: %+v err=%v", pr2, err)
	}

	// 3. Pairing for same key in DIFFERENT tenant-b must fail closed (CodeEnrollAuth).
	if err := db.CreatePairingRequest("p3", "3333-4444-5555", "poll-3", []byte("ver3"), pub, keyID, "127.0.0.1", exp); err != nil {
		t.Fatal(err)
	}
	if _, err := ApprovePairingRequest(db, "3333-4444-5555", "tenant-b"); err == nil || apperr.CodeOf(err) != apperr.CodeEnrollAuth {
		t.Fatalf("cross-tenant re-approval should fail with CodeEnrollAuth, got %v", err)
	}
}

func TestPairStatusStoreFaultReturns503Not404(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	// Close DB to force a CodeStoreFault on both endpoints.
	_ = db.Close()

	// handlePairStatus must return 503, NOT 404.
	reqBody, _ := json.Marshal(map[string]string{"poll_id": "any", "poll_secret": "any"})
	r := httptest.NewRequest(http.MethodPost, "/v1/agent/pair-status", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	s.handlePairStatus(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("handlePairStatus on store fault: got %d, want 503", w.Code)
	}

	// handlePairRequest must return 503, NOT 429.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	reqBody2, _ := json.Marshal(map[string]string{"public_key": base64.StdEncoding.EncodeToString(pub)})
	r2 := httptest.NewRequest(http.MethodPost, "/v1/agent/pair-request", bytes.NewReader(reqBody2))
	w2 := httptest.NewRecorder()
	s.handlePairRequest(w2, r2)
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("handlePairRequest on store fault: got %d, want 503", w2.Code)
	}
}

func TestApprovePairingConcurrentSingleWinner(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(pub)
	keyID := "key-" + hex.EncodeToString(sum[:identity.KeyIDBytes])
	exp := time.Now().UTC().Add(10 * time.Minute)
	if err := db.CreatePairingRequest("p-conc", "9999-8888-7777", "poll-conc", []byte("ver"), pub, keyID, "127.0.0.1", exp); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := ApprovePairingRequest(db, "9999-8888-7777", "tenant-conc")
			results <- err
		}()
	}
	err1, err2 := <-results, <-results
	okCount, authErrCount := 0, 0
	for _, e := range []error{err1, err2} {
		if e == nil {
			okCount++
		} else if apperr.CodeOf(e) == apperr.CodeEnrollAuth {
			authErrCount++
		} else {
			t.Fatalf("unexpected non-auth error from concurrent approve: %v", e)
		}
	}
	if okCount != 1 || authErrCount != 1 {
		t.Fatalf("expected 1 success + 1 CodeEnrollAuth, got ok=%d authErr=%d (err1=%v, err2=%v)", okCount, authErrCount, err1, err2)
	}
}

func TestExpiredPairingRowsDoNotExhaustGlobalCap(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	tx, err := db.SQL().Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < pairingGlobalMax+50; i++ {
		_, err := tx.Exec(
			`INSERT INTO pairing_requests(id, display_code, poll_id, poll_verifier, public_key, key_id, source_ip, status, created_at, expires_at)
			 VALUES(?,?,?,X'01',X'00','key-x','127.0.0.1','pending',?,?)`,
			"exp-"+string(rune('a'+i%26))+hex.EncodeToString([]byte{byte(i >> 8), byte(i)}),
			hex.EncodeToString([]byte{byte(i >> 8), byte(i), 0xaa, 0xbb}),
			"poll-"+hex.EncodeToString([]byte{byte(i >> 8), byte(i)}),
			past, past)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	reqBody, _ := json.Marshal(map[string]string{"public_key": base64.StdEncoding.EncodeToString(pub)})
	r := httptest.NewRequest(http.MethodPost, "/v1/agent/pair-request", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	s.handlePairRequest(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("fresh pair-request blocked by expired rows: got %d (%s), want 200", w.Code, w.Body.String())
	}
}
