package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ocliv/internal/identity"
	"ocliv/internal/store"
)

func TestP0ExpiredPersistentLeaseNeverResurrectsOldVisitorAuthority(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = enrollTestKey(t, db.SQL(), "key-exp-persist", "tenant-exp")

	label := "expapp"
	ls, att, err := s.insertLease("tenant-exp", "key-exp-persist", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true, TTLSeconds: 3600},
		time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("insertLease: %v", err)
	}
	_, rawTok, ok := strings.Cut(att.ShareURL, "#t=")
	if !ok || rawTok == "" {
		t.Fatalf("missing share token")
	}

	// Visitor redeems share token -> gets browser session cookie.
	body, _ := json.Marshal(map[string]string{"token": rawTok})
	redeemReq := httptest.NewRequest(http.MethodPost, "https://"+ls.Hostname+"/_ocliv/redeem", bytes.NewReader(body))
	redeemReq.Host = ls.Hostname
	redeemReq.Header.Set("Content-Type", "application/json")
	redeemReq.Header.Set("Origin", "https://"+ls.Hostname)
	redeemW := httptest.NewRecorder()
	s.handleRedeem(redeemW, redeemReq)
	if redeemW.Code != http.StatusOK {
		t.Fatalf("redeem status=%d body=%s", redeemW.Code, redeemW.Body.String())
	}
	oldCookie := redeemW.Result().Cookies()[0]

	// Lease reaches terminal EXPIRED state.
	if _, err := db.SQL().Exec(`UPDATE leases SET status='EXPIRED' WHERE id=?`, ls.ID); err != nil {
		t.Fatal(err)
	}

	// Same owner republishes under the same name: MUST mint a NEW lease ID and
	// MUST NOT resurrect the expired lease or preserve old visitor cookie!
	ls2, _, err := s.insertLease("tenant-exp", "key-exp-persist", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true, TTLSeconds: 3600},
		time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("republish after expiry failed: %v", err)
	}
	if ls2.ID == ls.ID {
		t.Fatalf("P0 REGRESSION: expired persistent lease %s was resurrected in place", ls.ID)
	}
	if ls2.Hostname != ls.Hostname {
		t.Fatalf("expected same hostname %s, got %s", ls.Hostname, ls2.Hostname)
	}
	rtNew := &routeTarget{LeaseID: ls2.ID, TokenGen: tokenGeneration(t, db.SQL(), ls2.ID)}
	if s.checkCookieSession(rtNew, oldCookie.Value) {
		t.Fatal("P0 REGRESSION: old visitor cookie survived EXPIRED lease replacement")
	}
}

func TestP0PersistentModeInResumeAndUnnamedPersistentRejected(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = enrollTestKey(t, db.SQL(), "key-mode-chk", "tenant-mode")

	// 1. Unnamed persistent lease MUST be rejected.
	if _, _, err := s.allocateOrResume("tenant-mode", "key-mode-chk", LeaseIntent{
		Port: 3000, Ready: true, Persistent: true, Name: "",
	}); err == nil {
		t.Fatal("expected unnamed persistent lease to be rejected")
	}

	// 2. Named persistent lease cannot be resumed with Persistent=false.
	label := "modechk"
	ls, _, err := s.insertLease("tenant-mode", "key-mode-chk", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true},
		time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.resumeLease("tenant-mode", "key-mode-chk", LeaseIntent{
		Port: 3000, AccessMode: "protected", Name: label, LeaseID: ls.ID, Persistent: false,
	}); err == nil {
		t.Fatal("expected resume with mismatched Persistent=false to be denied")
	}
}

func TestP0RealRelayRestartPreservesVisitorCookieWithPersistentHMACKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ocliv.db")

	// Process A: load/create persistent visitor HMAC key + open DB + start Server A.
	keyA, err := LoadOrCreateVisitorKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateVisitorKey A: %v", err)
	}
	dbA, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	srvA, err := New(Options{DB: dbA, Namespace: "t.example.test", RelayHost: "relay.example.test", ServerKey: keyA})
	if err != nil {
		t.Fatal(err)
	}
	_ = enrollTestKey(t, dbA.SQL(), "key-restart-hmac", "tenant-hmac")

	label := "hmacapp"
	ls, att, err := srvA.insertLease("tenant-hmac", "key-restart-hmac", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	_, rawTok, _ := strings.Cut(att.ShareURL, "#t=")
	body, _ := json.Marshal(map[string]string{"token": rawTok})
	redeemReq := httptest.NewRequest(http.MethodPost, "https://"+ls.Hostname+"/_ocliv/redeem", bytes.NewReader(body))
	redeemReq.Host = ls.Hostname
	redeemReq.Header.Set("Content-Type", "application/json")
	redeemReq.Header.Set("Origin", "https://"+ls.Hostname)
	redeemW := httptest.NewRecorder()
	srvA.handleRedeem(redeemW, redeemReq)
	if redeemW.Code != http.StatusOK {
		t.Fatalf("redeem failed: %d", redeemW.Code)
	}
	cookie := redeemW.Result().Cookies()[0]
	tokenGen := tokenGeneration(t, dbA.SQL(), ls.ID)
	_ = dbA.Close()

	// Process B: brand-new Server B loading same DB + same persistent HMAC key.
	keyB, err := LoadOrCreateVisitorKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateVisitorKey B: %v", err)
	}
	dbB, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	srvB, err := New(Options{DB: dbB, Namespace: "t.example.test", RelayHost: "relay.example.test", ServerKey: keyB})
	if err != nil {
		t.Fatal(err)
	}
	if !srvB.checkCookieSession(&routeTarget{LeaseID: ls.ID, TokenGen: tokenGen}, cookie.Value) {
		t.Fatal("visitor cookie failed across real relay restart with persistent HMAC key")
	}
	_ = dbB.Close()

	// Negative control: explicit RotateVisitorKey -> Server C invalidates old cookie!
	keyC, err := RotateVisitorKey(dir)
	if err != nil {
		t.Fatalf("RotateVisitorKey: %v", err)
	}
	dbC, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dbC.Close()
	srvC, err := New(Options{DB: dbC, Namespace: "t.example.test", RelayHost: "relay.example.test", ServerKey: keyC})
	if err != nil {
		t.Fatal(err)
	}
	if srvC.checkCookieSession(&routeTarget{LeaseID: ls.ID, TokenGen: tokenGen}, cookie.Value) {
		t.Fatal("visitor cookie remained valid after explicit visitor HMAC key rotation")
	}
}

func TestP0ChallengeAdvertisesPersistentCapability(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = enrollTestKey(t, db.SQL(), "key-cap", "tenant-cap")

	req := httptest.NewRequest(http.MethodPost, "/v1/agent/challenge", strings.NewReader(`{"key_id":"key-cap"}`))
	w := httptest.NewRecorder()
	s.handleChallenge(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", w.Code, w.Body.String())
	}
	var ch challengeResp
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range ch.Capabilities {
		if c == CapabilityPersistentNamedLeases {
			found = true
		}
	}
	if !found {
		t.Fatalf("challenge missing capability %q: %+v", CapabilityPersistentNamedLeases, ch.Capabilities)
	}
}

func signedMgmtRequestV2(t *testing.T, priv ed25519.PrivateKey, keyID, method, path string, body []byte) (*http.Request, string) {
	t.Helper()
	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(nonceRaw); err != nil {
		t.Fatal(err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceRaw)
	ts := time.Now().UTC()
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	msg := []byte(fmt.Sprintf("ocliv-mgmt-v2\n%s\n%s\n%s\n%d\n%s\n%s",
		keyID, method, path, ts.Unix(), nonce, digest))
	sig := ed25519.Sign(priv, msg)
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("X-Ocliv-Key", keyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig-Version", "2")
	req.Header.Set("X-Ocliv-Body-SHA256", digest)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	return req, nonce
}

func TestP1AgentKeyRotateTransfersOwnershipAndRevokesOldKey(t *testing.T) {
	s, db := newLifecycleServer(t)
	oldPriv := enrollTestKey(t, db.SQL(), "key-rot-old", "tenant-rot")

	label := "rotapp"
	ls, _, err := s.insertLease("tenant-rot", "key-rot-old", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true, TTLSeconds: 3600},
		time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("insertLease: %v", err)
	}
	liveFabricatedSession(t, s, ls.ID, 1)
	if _, live := s.liveSession(ls.ID); !live {
		t.Fatal("expected live session before rotation")
	}

	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantNewKeyID := "key-" + string(identity.KeyIDFor(newPub))

	// P0-4 negative check 1: mutating 1 byte of JSON body with a valid v2 signature MUST be rejected.
	origBody := []byte(`{"new_public_key":"` + base64.StdEncoding.EncodeToString(newPub) + `","new_key_proof":"AAAA"}`)
	tamperedReq, _ := signedMgmtRequestV2(t, oldPriv, "key-rot-old", http.MethodPost, "/v1/agent/key/rotate", origBody)
	tamperedBody := append([]byte(nil), origBody...)
	tamperedBody[len(tamperedBody)-2] = 'B'
	tamperedReq.Body = io.NopCloser(bytes.NewReader(tamperedBody))
	wTamper := httptest.NewRecorder()
	s.handleAgentKeyRotate(wTamper, tamperedReq)
	if wTamper.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for tampered JSON body under v2 signature, got %d", wTamper.Code)
	}

	// P0-4 negative check 2: missing/invalid new_key_proof MUST be rejected.
	badProofBody, _ := json.Marshal(map[string]string{
		"new_public_key": base64.StdEncoding.EncodeToString(newPub),
		"new_key_proof":  base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	})
	badProofReq, _ := signedMgmtRequestV2(t, oldPriv, "key-rot-old", http.MethodPost, "/v1/agent/key/rotate", badProofBody)
	wBadProof := httptest.NewRecorder()
	s.handleAgentKeyRotate(wBadProof, badProofReq)
	if wBadProof.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid new_key_proof, got %d (%s)", wBadProof.Code, wBadProof.Body.String())
	}

	// Valid v2 signature + valid new_key_proof succeeds.
	nonceRaw := make([]byte, 16)
	_, _ = rand.Read(nonceRaw)
	nonce := base64.StdEncoding.EncodeToString(nonceRaw)
	proofMsg := []byte(fmt.Sprintf("ocliv-key-rotation-v1\n%s\n%s\n%s", "key-rot-old", wantNewKeyID, nonce))
	proofSig := ed25519.Sign(newPriv, proofMsg)
	payload, _ := json.Marshal(map[string]string{
		"new_public_key": base64.StdEncoding.EncodeToString(newPub),
		"new_key_proof":  base64.StdEncoding.EncodeToString(proofSig),
	})
	ts := time.Now().UTC()
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	msg := []byte(fmt.Sprintf("ocliv-mgmt-v2\n%s\n%s\n%s\n%d\n%s\n%s",
		"key-rot-old", http.MethodPost, "/v1/agent/key/rotate", ts.Unix(), nonce, digest))
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/key/rotate", bytes.NewReader(payload))
	req.Header.Set("X-Ocliv-Key", "key-rot-old")
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig-Version", "2")
	req.Header.Set("X-Ocliv-Body-SHA256", digest)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(ed25519.Sign(oldPriv, msg)))
	w := httptest.NewRecorder()
	s.handleAgentKeyRotate(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		OldKeyID          string `json:"old_key_id"`
		NewKeyID          string `json:"new_key_id"`
		LeasesTransferred int64  `json:"leases_transferred"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.NewKeyID != wantNewKeyID || out.LeasesTransferred != 1 {
		t.Fatalf("unexpected rotate response: %+v", out)
	}

	// P0-3: old live session MUST be evicted immediately on rotation.
	if _, live := s.liveSession(ls.ID); live {
		t.Fatal("P0-3: live session authenticated under revoked old key survived rotation")
	}

	// Old key must now be rejected.
	reqOld := signedMgmtRequest(t, oldPriv, "key-rot-old", http.MethodGet, "/v1/agent/leases")
	wOld := httptest.NewRecorder()
	s.handleAgentLeases(wOld, reqOld)
	if wOld.Code != http.StatusForbidden {
		t.Fatalf("old key must be rejected after rotate, got %d", wOld.Code)
	}

	// New key owns the transferred lease.
	reqNew := signedMgmtRequest(t, newPriv, wantNewKeyID, http.MethodGet, "/v1/agent/lease/"+ls.ID+"/status")
	wNew := httptest.NewRecorder()
	s.handleAgentLease(wNew, reqNew)
	if wNew.Code != http.StatusOK {
		t.Fatalf("new key must access transferred lease, got %d (%s)", wNew.Code, wNew.Body.String())
	}
}

// TestP0SelfRevokeTerminatesLiveSessionLeaseAndVisitorAuthority proves P0-1:
// POST /v1/agent/key/revoke revokes the key, revokes ACTIVE/RECONNECTING leases,
// revokes visitor tokens & sessions, evicts live sessions, and blocks re-attach.
func TestP0SelfRevokeTerminatesLiveSessionLeaseAndVisitorAuthority(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-logout-self", "tenant-logout")

	label := "logoutapp"
	ls, att, err := s.insertLease("tenant-logout", "key-logout-self", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true, TTLSeconds: 3600},
		time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("insertLease: %v", err)
	}
	liveFabricatedSession(t, s, ls.ID, 1)
	if _, live := s.liveSession(ls.ID); !live {
		t.Fatal("expected live session before self-revoke")
	}
	// Redeem share token to create a real visitor session cookie.
	tokIdx := strings.Index(att.ShareURL, "#t=")
	rawTok := att.ShareURL[tokIdx+3:]
	redeemReq := httptest.NewRequest(http.MethodPost, "https://"+ls.Hostname+"/_ocliv/redeem",
		strings.NewReader(`{"token":"`+rawTok+`"}`))
	redeemReq.Host = ls.Hostname
	redeemReq.Header.Set("Origin", "https://"+ls.Hostname)
	redeemReq.Header.Set("Content-Type", "application/json")
	wRedeem := httptest.NewRecorder()
	s.handleRedeem(wRedeem, redeemReq)
	if wRedeem.Code != http.StatusOK {
		t.Fatalf("redeem status=%d body=%s", wRedeem.Code, wRedeem.Body.String())
	}

	req, _ := signedMgmtRequestV2(t, priv, "key-logout-self", http.MethodPost, "/v1/agent/key/revoke", nil)
	w := httptest.NewRecorder()
	s.handleAgentKeyRevoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("self-revoke status=%d body=%s", w.Code, w.Body.String())
	}

	// 1. Live session must be evicted immediately.
	if _, live := s.liveSession(ls.ID); live {
		t.Fatal("P0-1: live session survived self-revoke")
	}
	// 2. Key status and lease status must both be revoked.
	var kst, lst string
	if err := db.SQL().QueryRow(`SELECT status FROM agent_keys WHERE id='key-logout-self'`).Scan(&kst); err != nil || kst != "revoked" {
		t.Fatalf("key status=%q err=%v, want revoked", kst, err)
	}
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, ls.ID).Scan(&lst); err != nil || lst != "REVOKED" {
		t.Fatalf("lease status=%q err=%v, want REVOKED", lst, err)
	}
	// 3. Visitor sessions must be revoked in SQLite.
	var activeSess int
	_ = db.SQL().QueryRow(`SELECT COUNT(*) FROM visitor_sessions WHERE lease_id=? AND revoked_at IS NULL`, ls.ID).Scan(&activeSess)
	if activeSess != 0 {
		t.Fatalf("P0-1: %d visitor sessions still unrevoked after self-revoke", activeSess)
	}
	// 4. Re-attach with revoked key must be denied.
	if _, _, err := s.allocateOrResume("tenant-logout", "key-logout-self", LeaseIntent{
		Port: 3000, Ready: true, Version: "1", LeaseID: ls.ID, Persistent: true, Name: label,
	}); err == nil {
		t.Fatal("revoked key was allowed to resume lease")
	}
	// 5. Subsequent management call must be denied.
	reqAfter := signedMgmtRequest(t, priv, "key-logout-self", http.MethodGet, "/v1/agent/leases")
	wAfter := httptest.NewRecorder()
	s.handleAgentLeases(wAfter, reqAfter)
	if wAfter.Code != http.StatusForbidden {
		t.Fatalf("expected 403 after self-revoke, got %d", wAfter.Code)
	}
}

// TestP0ActivePersistentLeaseWithPastExpiryNeverPreservesVisitorAuthority proves P0-5:
// an ACTIVE persistent lease whose expires_at is in the past must NOT be rebound in-place.
func TestP0ActivePersistentLeaseWithPastExpiryNeverPreservesVisitorAuthority(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = enrollTestKey(t, db.SQL(), "key-past-exp", "tenant-past-exp")

	label := "pastexp"
	ls1, _, err := s.insertLease("tenant-past-exp", "key-past-exp", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true, TTLSeconds: 3600},
		time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("insertLease: %v", err)
	}
	// Force expires_at = now - 1s while keeping status='ACTIVE'.
	past := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	if _, err := db.SQL().Exec(`UPDATE leases SET expires_at=? WHERE id=?`, past, ls1.ID); err != nil {
		t.Fatal(err)
	}
	ls2, _, err := s.insertLease("tenant-past-exp", "key-past-exp", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true, TTLSeconds: 3600},
		time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("second insertLease: %v", err)
	}
	if ls2.ID == ls1.ID {
		t.Fatalf("P0-5: expired ACTIVE persistent lease %s was revived in-place instead of replaced", ls1.ID)
	}
}

// TestP0AccessRevokeRevokesVisitorCredentialsWithoutRevokingLease proves P0-6:
// POST /v1/agent/lease/<id>/access/revoke revokes visitor tokens and sessions
// and bumps token_generation, while keeping the lease ACTIVE.
func TestP0AccessRevokeRevokesVisitorCredentialsWithoutRevokingLease(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-vis-rev", "tenant-vis-rev")

	label := "visrev"
	ls, _, err := s.insertLease("tenant-vis-rev", "key-vis-rev", label,
		LeaseIntent{Port: 3000, AccessMode: "protected", Persistent: true, TTLSeconds: 3600},
		time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := signedMgmtRequestV2(t, priv, "key-vis-rev", http.MethodPost, "/v1/agent/lease/"+ls.ID+"/access/revoke", nil)
	w := httptest.NewRecorder()
	s.handleAgentLease(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("access/revoke status=%d body=%s", w.Code, w.Body.String())
	}
	var st string
	var tokGen int64
	if err := db.SQL().QueryRow(`SELECT status, token_generation FROM leases WHERE id=?`, ls.ID).Scan(&st, &tokGen); err != nil {
		t.Fatal(err)
	}
	if st != "ACTIVE" {
		t.Fatalf("P0-6: access/revoke changed lease status to %q, want ACTIVE", st)
	}
	if tokGen < 1 {
		t.Fatalf("P0-6: token_generation=%d, want >= 1", tokGen)
	}
	var unrevokedTokens int
	_ = db.SQL().QueryRow(`SELECT COUNT(*) FROM access_tokens WHERE lease_id=? AND revoked_at IS NULL`, ls.ID).Scan(&unrevokedTokens)
	if unrevokedTokens != 0 {
		t.Fatalf("P0-6: %d access tokens still unrevoked", unrevokedTokens)
	}
}

// TestP1VisitorKeyRejectsSymlinkAndPermissiveMode proves P1-5 hardened key loading.
func TestP1VisitorKeyRejectsSymlinkAndPermissiveMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.key")
	if err := os.WriteFile(target, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, visitorKeyFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateVisitorKey(dir); err == nil {
		t.Fatal("P1-5: expected symlinked visitor-hmac.key to be rejected")
	}

	dir2 := t.TempDir()
	keyPath2 := filepath.Join(dir2, visitorKeyFileName)
	if err := os.WriteFile(keyPath2, []byte(strings.Repeat("cd", 32)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath2, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateVisitorKey(dir2); err == nil {
		t.Fatal("P1-5: expected world-readable visitor-hmac.key (0644) to be rejected")
	}
}
