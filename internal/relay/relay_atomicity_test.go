package relay

// Transaction-atomicity regression tests for credential rotation and
// lease allocation (god-object review findings 3 / actions 1-3).
//
// Pre-fix, both paths committed durable state before minting the new
// token: rotation revoked the old credentials and then minted outside
// the transaction, and insertLease committed the lease row before
// issuing the initial share token. A mint/insert failure left a
// tokenless lease behind. Now the token verifier inserts inside the
// same transaction, so failure rolls everything back.
//
// Fault injection: a BEFORE INSERT trigger forces every access_tokens
// INSERT to fail while UPDATEs still succeed — exactly the
// post-commit-mint-failure interleaving.

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func enrollTestKey(t *testing.T, db *sql.DB, keyID, tenant string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT OR IGNORE INTO tenants(id, status, created_at) VALUES(?,?,?)`,
		tenant, "active", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,?,?)`,
		keyID, tenant, []byte(pub), "active", now); err != nil {
		t.Fatal(err)
	}
	return priv
}

func signedMgmtRequest(t *testing.T, priv ed25519.PrivateKey, keyID, method, path string) *http.Request {
	t.Helper()
	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(nonceRaw); err != nil {
		t.Fatal(err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceRaw)
	ts := time.Now().UTC()
	msg := []byte(fmt.Sprintf("ocliv-mgmt-v1\n%s\n%s\n%s\n%d\n%s",
		keyID, method, path, ts.Unix(), nonce))
	sig := ed25519.Sign(priv, msg)
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("X-Ocliv-Key", keyID)
	r.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	r.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	r.Header.Set("X-Ocliv-Nonce", nonce)
	return r
}

func validTokenCount(t *testing.T, db *sql.DB, leaseID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM access_tokens WHERE lease_id=? AND revoked_at IS NULL`,
		leaseID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func tokenGeneration(t *testing.T, db *sql.DB, leaseID string) int64 {
	t.Helper()
	var g int64
	if err := db.QueryRow(`SELECT token_generation FROM leases WHERE id=?`, leaseID).Scan(&g); err != nil {
		t.Fatal(err)
	}
	return g
}

// failTokenInserts installs a trigger so every access_tokens INSERT fails
// while UPDATEs keep working. Cleanup drops it.
func failTokenInserts(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`CREATE TRIGGER probe_fail_token_insert BEFORE INSERT ON access_tokens
		BEGIN SELECT RAISE(ABORT, 'probe token insert fault'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP TRIGGER IF EXISTS probe_fail_token_insert`) })
}

// TestInsertTokenRowHonorsTransaction proves the token insert helper
// actually writes through the caller's transaction: rollback must leave
// no row, commit must persist exactly one. A regression to a direct-DB
// insert would survive the rollback and fail the first assertion.
func TestInsertTokenRowHonorsTransaction(t *testing.T) {
	_, db := newLifecycleServer(t)
	insertLeaseRow(t, db, "lse-tx", "ACTIVE", 1, nil)

	raw, row, err := prepareAccessToken("visitor", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || row.verifier == "" {
		t.Fatal("prepared token missing secret or verifier")
	}
	tx, err := db.SQL().Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := insertAccessTokenRow(tx, "lse-tx", "visitor", 1, row); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if n := validTokenCount(t, db.SQL(), "lse-tx"); n != 0 {
		t.Fatalf("rolled-back token insert survived: %d rows", n)
	}

	raw2, row2, err := prepareAccessToken("visitor", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw2
	tx2, err := db.SQL().Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := insertAccessTokenRow(tx2, "lse-tx", "visitor", 1, row2); err != nil {
		_ = tx2.Rollback()
		t.Fatal(err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatal(err)
	}
	if n := validTokenCount(t, db.SQL(), "lse-tx"); n != 1 {
		t.Fatalf("committed token insert missing: %d rows", n)
	}
}

// TestAllocateIsAtomicOnTokenFailure: when the initial share-token insert
// fails, allocation must fail without leaving a committed lease row.
// Pre-fix, the lease INSERT committed first, so the error path left an
// orphaned lease with no share URL.
func TestAllocateIsAtomicOnTokenFailure(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-atomic", "tenant-test")
	_ = priv
	failTokenInserts(t, db.SQL())

	label := "atomicprobe"
	_, _, err := s.insertLease("tenant-test", "key-atomic", label,
		LeaseIntent{Port: 3000}, time.Now().UTC(), &label)
	if err == nil {
		t.Fatal("insertLease succeeded while token inserts faulted")
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM leases WHERE hostname=?`,
		label+".t.example.test").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("orphaned lease row committed without share token: %d rows", n)
	}
}

// TestAllocateMintsExactlyOneToken: the success path allocates a lease
// whose share URL is backed by exactly one durable unrevoked token.
func TestAllocateMintsExactlyOneToken(t *testing.T) {
	s, db := newLifecycleServer(t)
	enrollTestKey(t, db.SQL(), "key-atomic-ok", "tenant-test")

	label := "atomicsuccess"
	ls, att, err := s.insertLease("tenant-test", "key-atomic-ok", label,
		LeaseIntent{Port: 3000}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	if att.ShareURL == "" || !strings.Contains(att.ShareURL, "#t=") {
		t.Fatalf("protected lease missing share secret: %q", att.ShareURL)
	}
	if n := validTokenCount(t, db.SQL(), ls.ID); n != 1 {
		t.Fatalf("expected exactly one valid token, got %d", n)
	}
}

// TestRotateIsAtomicOnTokenFailure drives the production rotate handler
// with token inserts faulted: rotation must fail closed with the previous
// credential still valid and the generation unchanged. Pre-fix, the
// revocation committed first and the failed mint left zero valid tokens.
func TestRotateIsAtomicOnTokenFailure(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-rot", "tenant-test")
	label := "rotprobe"
	ls, _, err := s.insertLease("tenant-test", "key-rot", label,
		LeaseIntent{Port: 3000}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	genBefore := tokenGeneration(t, db.SQL(), ls.ID)
	if n := validTokenCount(t, db.SQL(), ls.ID); n != 1 {
		t.Fatalf("setup: expected one valid token, got %d", n)
	}

	failTokenInserts(t, db.SQL())
	path := "/v1/agent/lease/" + ls.ID + "/rotate"
	w := httptest.NewRecorder()
	s.handleAgentLease(w, signedMgmtRequest(t, priv, "key-rot", http.MethodPost, path))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("faulted rotate returned %d, want 500", w.Code)
	}
	if g := tokenGeneration(t, db.SQL(), ls.ID); g != genBefore {
		t.Fatalf("faulted rotate bumped generation %d -> %d", genBefore, g)
	}
	if n := validTokenCount(t, db.SQL(), ls.ID); n != 1 {
		t.Fatalf("faulted rotate left %d valid tokens, want the original 1", n)
	}
}

// TestRotateSuccessLeavesSingleValidToken pins the happy-path invariant:
// exactly one unrevoked token, generation bumped by one.
func TestRotateSuccessLeavesSingleValidToken(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-rot-ok", "tenant-test")
	label := "rotok"
	ls, _, err := s.insertLease("tenant-test", "key-rot-ok", label,
		LeaseIntent{Port: 3000}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	genBefore := tokenGeneration(t, db.SQL(), ls.ID)

	path := "/v1/agent/lease/" + ls.ID + "/rotate"
	w := httptest.NewRecorder()
	s.handleAgentLease(w, signedMgmtRequest(t, priv, "key-rot-ok", http.MethodPost, path))
	if w.Code != http.StatusOK {
		t.Fatalf("rotate returned %d: %s", w.Code, w.Body.String())
	}
	if g := tokenGeneration(t, db.SQL(), ls.ID); g != genBefore+1 {
		t.Fatalf("generation %d, want %d", g, genBefore+1)
	}
	if n := validTokenCount(t, db.SQL(), ls.ID); n != 1 {
		t.Fatalf("expected exactly one valid token after rotate, got %d", n)
	}
}
