package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/identity"
	"ocliv/internal/store"
)

func TestPass6P0_5RotateVisitorKeyPreservesOwner(t *testing.T) {
	dir := t.TempDir()
	oldKey, err := LoadOrCreateVisitorKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateVisitorKey: %v", err)
	}
	keyPath := filepath.Join(dir, visitorKeyFileName)
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("syscall.Stat_t unavailable")
	}
	wantUID, wantGID := int(st.Uid), int(st.Gid)

	var chownCalled bool
	var gotUID, gotGID int
	newKey, err := rotateVisitorKeyWithChown(dir, func(f *os.File, uid, gid int) error {
		chownCalled = true
		gotUID, gotGID = uid, gid
		return f.Chown(uid, gid)
	})
	if err != nil {
		t.Fatalf("rotateVisitorKeyWithChown: %v", err)
	}
	if !chownCalled {
		t.Fatalf("expected chown callback to be invoked to preserve existing key owner")
	}
	if gotUID != wantUID || gotGID != wantGID {
		t.Fatalf("expected chown(%d,%d), got chown(%d,%d)", wantUID, wantGID, gotUID, gotGID)
	}
	if len(newKey) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(newKey))
	}
	if VisitorKeyFingerprint(newKey) == VisitorKeyFingerprint(oldKey) {
		t.Fatalf("rotated key matched old key")
	}
	fiAfter, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fiAfter.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 mode after rotation, got %o", fiAfter.Mode().Perm())
	}
}

func TestPass6P1_2SelfRevokeAuditsAgentActor(t *testing.T) {
	s, db := newLifecycleServer(t)
	kp, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := "key-" + string(kp.ID())
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.SQL().Exec(`INSERT OR IGNORE INTO tenants(id,status,created_at) VALUES('tenant-self','active',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO agent_keys(id,tenant_id,ed25519_public,status,created_at) VALUES(?,?,?,'active',?)`,
		keyID, "tenant-self", []byte(kp.Public()), now); err != nil {
		t.Fatal(err)
	}

	ts := time.Now().UTC()
	var nonceRaw [16]byte
	_, _ = rand.Read(nonceRaw[:])
	nonce := base64.StdEncoding.EncodeToString(nonceRaw[:])
	path := "/v1/agent/key/revoke"
	sig := ed25519.Sign(kp.Private(), agent.MgmtMessage(keyID, http.MethodPost, path, ts, nonce))

	req := httptest.NewRequest(http.MethodPost, "https://"+s.relayHost+path, nil)
	req.Host = s.relayHost
	req.Header.Set("X-Ocliv-Key", keyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	req.Header.Set("X-Ocliv-Nonce", nonce)
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))

	w := httptest.NewRecorder()
	s.handleAgentKeyRevoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("self-revoke failed: status=%d body=%s", w.Code, w.Body.String())
	}

	var agentRows, opRows int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE category='agent_key_revoke' AND actor='agent'`).Scan(&agentRows); err != nil {
		t.Fatal(err)
	}
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE actor='operator'`).Scan(&opRows); err != nil {
		t.Fatal(err)
	}
	if agentRows < 1 {
		t.Fatalf("expected actor='agent' audit event for self-revoke, got %d", agentRows)
	}
	if opRows != 0 {
		t.Fatalf("P1-2 REGRESSION: self-revoke wrote %d actor='operator' audit rows", opRows)
	}
}

func TestPass6P1_3RevokeAgentKeyTombstonesClosedLeasePublications(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = enrollTestKey(t, db.SQL(), "key-pub-owner", "tenant-pub")

	now := time.Now().UTC().Format(time.RFC3339)
	exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	// Insert a CLOSED lease and an active mcp_publication owned by key-pub-owner.
	if _, err := db.SQL().Exec(`INSERT INTO leases(id,tenant_id,agent_key_id,hostname,label,port,access_mode,status,generation,created_at,expires_at)
		VALUES('lse-closed-pub','tenant-pub','key-pub-owner','closed.t.relay.example','closed',3000,'protected','CLOSED',1,?,?)`, now, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO mcp_publications(route_id,tenant_id,owner_key_id,external_host,profile,pub_name,target_path,lease_id,created_at,updated_at)
		VALUES('pub-closed-1','tenant-pub','key-pub-owner','closed.t.relay.example','ocliv-managed','closed','/mcp','lse-closed-pub',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}

	if _, err := s.RevokeAgentKeyAs("key-pub-owner", "agent", "self_logout"); err != nil {
		t.Fatalf("RevokeAgentKeyAs: %v", err)
	}
	var revokedAt string
	if err := db.SQL().QueryRow(`SELECT COALESCE(revoked_at,'') FROM mcp_publications WHERE route_id='pub-closed-1'`).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt == "" {
		t.Fatalf("P1-3 REGRESSION: publication on CLOSED lease was not tombstoned when owner key was revoked")
	}
}

func TestPass6P2RestoreBackupInvalidatesSessionsOnFingerprintMismatch(t *testing.T) {
	dataDir := t.TempDir()
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	if _, err := rand.Read(keyA); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(keyB); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dataDir, visitorKeyFileName)
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(keyA)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(dataDir, relayDBName)
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{DB: db, Namespace: "t.relay.example", RelayHost: "relay.example", ServerKey: keyA})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	_ = s
	now := time.Now().UTC().Format(time.RFC3339)
	exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	_ = enrollTestKey(t, db.SQL(), "key-bk", "tenant-bk")
	if _, err := db.SQL().Exec(`INSERT INTO leases(id,tenant_id,agent_key_id,hostname,label,port,access_mode,status,generation,created_at,expires_at)
		VALUES('lse-bk','tenant-bk','key-bk','bk.t.relay.example','bk',3000,'protected','ACTIVE',1,?,?)`, now, exp); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("sess-secret"))
	if _, err := db.SQL().Exec(`INSERT INTO visitor_sessions(id,lease_id,session_verifier,created_at,idle_expires_at,absolute_expires_at)
		VALUES('vs-1','lse-bk',?,?,?,?)`, hex.EncodeToString(h[:]), now, exp, exp); err != nil {
		t.Fatal(err)
	}
	bkPath := filepath.Join(t.TempDir(), "backup.db")
	if err := BackupState(db, bkPath); err != nil {
		db.Close()
		t.Fatalf("BackupState: %v", err)
	}
	db.Close()

	// Replace visitor-hmac.key with a different valid 32-byte keyB before restore.
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(keyB)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(dataDir, bkPath, false, true); err != nil {
		t.Fatalf("RestoreState: %v", err)
	}

	db2, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var revokedAt string
	if err := db2.SQL().QueryRow(`SELECT COALESCE(revoked_at,'') FROM visitor_sessions WHERE id='vs-1'`).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt == "" {
		t.Fatalf("P2 REGRESSION: restored visitor session was not invalidated despite visitor-hmac.key fingerprint mismatch")
	}
}

func TestCapabilitiesEndpointBoundToRelayAuthority(t *testing.T) {
	s, _ := newLifecycleServer(t)
	// Relay authority MUST return 200 with mgmt_body_sig_v2.
	req := httptest.NewRequest(http.MethodGet, "https://"+s.relayHost+"/v1/agent/capabilities", nil)
	req.Host = s.relayHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on relay host /v1/agent/capabilities, got %d body=%s", w.Code, w.Body.String())
	}
	// Tunnel host MUST fail closed with 421 Misdirected Request.
	req2 := httptest.NewRequest(http.MethodGet, "https://app.t."+s.relayHost+"/v1/agent/capabilities", nil)
	req2.Host = "app.t." + s.relayHost
	w2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421 on tunnel host /v1/agent/capabilities, got %d", w2.Code)
	}
}
