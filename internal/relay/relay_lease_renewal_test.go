package relay

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/lease"
)

func renewalFixture(t *testing.T) (*Server, ed25519.PrivateKey, string) {
	t.Helper()
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "renew-key", "tenant-test")
	insertLeaseRow(t, db, "renew-lease", "ACTIVE", 7, nil)
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if _, err := db.SQL().Exec(`UPDATE leases SET agent_key_id='renew-key', expires_at=? WHERE id='renew-lease'`, expires); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, "renew-lease", 7)
	return s, priv, "renew-lease"
}

func postLeaseRenewal(t *testing.T, s *Server, priv ed25519.PrivateKey, leaseID string, generation uint64, ttl int64) *httptest.ResponseRecorder {
	return postLeaseRenewalFor(t, s, priv, "renew-key", leaseID, generation, ttl, "none")
}

func postLeaseRenewalFor(t *testing.T, s *Server, priv ed25519.PrivateKey, keyID, leaseID string, generation uint64, ttl int64, publicationID string) *httptest.ResponseRecorder {
	t.Helper()
	path := fmt.Sprintf("/v1/agent/lease/%s/renew/%d/%d/%s", leaseID, generation, ttl, publicationID)
	w := httptest.NewRecorder()
	s.handleAgentLease(w, signedMgmtRequest(t, priv, keyID, http.MethodPost, path))
	return w
}

func TestLeaseRenewalExtendsOnlyCurrentAuthorizedGeneration(t *testing.T) {
	s, priv, leaseID := renewalFixture(t)
	var oldExpiry string
	if err := s.db.SQL().QueryRow(`SELECT expires_at FROM leases WHERE id=?`, leaseID).Scan(&oldExpiry); err != nil {
		t.Fatal(err)
	}
	w := postLeaseRenewal(t, s, priv, leaseID, 7, 3600)
	if w.Code != http.StatusOK {
		t.Fatalf("renewal status=%d body=%s", w.Code, w.Body.String())
	}
	var result struct {
		ExpiresAt string `json:"lease_expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	newExpiry, err := time.Parse(time.RFC3339Nano, result.ExpiresAt)
	if err != nil || !newExpiry.After(time.Now().Add(3500*time.Second)) {
		t.Fatalf("renewal expiry=%q err=%v", result.ExpiresAt, err)
	}
	if result.ExpiresAt == oldExpiry {
		t.Fatalf("renewal did not extend expiry: %s", oldExpiry)
	}
}

func TestLeaseRenewalRejectsStaleGenerationAndRevocation(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "renew-key", "tenant-test")
	insertLeaseRow(t, db, "renew-stale", "ACTIVE", 7, nil)
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if _, err := db.SQL().Exec(`UPDATE leases SET agent_key_id='renew-key', expires_at=?, generation=8 WHERE id='renew-stale'`, expires); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, "renew-stale", 7)
	if w := postLeaseRenewal(t, s, priv, "renew-stale", 7, 3600); w.Code != http.StatusConflict {
		t.Fatalf("stale generation renewal status=%d, want 409", w.Code)
	}
	if _, err := db.SQL().Exec(`UPDATE leases SET generation=7 WHERE id='renew-stale'`); err != nil {
		t.Fatal(err)
	}
	if err := s.revokeLease("renew-stale"); err != nil {
		t.Fatal(err)
	}
	if w := postLeaseRenewal(t, s, priv, "renew-stale", 7, 3600); w.Code != http.StatusConflict {
		t.Fatalf("revoked lease renewal status=%d, want 409", w.Code)
	}
	var state string
	var after string
	if err := db.SQL().QueryRow(`SELECT status, expires_at FROM leases WHERE id='renew-stale'`).Scan(&state, &after); err != nil {
		t.Fatal(err)
	}
	if state != "REVOKED" || after != expires {
		t.Fatalf("revoked lease changed: status=%s expiry=%s want expiry=%s", state, after, expires)
	}
}

func TestLeaseRenewalIsBoundToPublication(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "renew-pub", "renew-pub.t.example.test", AccessModeMCPManaged, lease.StateActive, 7, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if _, err := db.SQL().Exec(`UPDATE leases SET expires_at=? WHERE id='renew-pub'`, expires); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, "renew-pub", 7)
	routeID := publishRoute(t, s, priv, "key-test", "renew-pub", "managed-oauth")
	if w := postLeaseRenewalFor(t, s, priv, "key-test", "renew-pub", 7, 3600, routeID); w.Code != http.StatusOK {
		t.Fatalf("owned publication renewal status=%d body=%s", w.Code, w.Body.String())
	}
	if w := postLeaseRenewalFor(t, s, priv, "key-test", "renew-pub", 7, 3600, "missing-route"); w.Code != http.StatusGone {
		t.Fatalf("missing publication renewal status=%d, want 410", w.Code)
	}
}

func TestLeaseRenewalPersistsAcrossRelayRestartAndRebind(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "renew-key", "tenant-test")
	insertLeaseRow(t, db, "renew-restart", "ACTIVE", 7, nil)
	if _, err := db.SQL().Exec(`UPDATE leases SET agent_key_id='renew-key', expires_at=? WHERE id='renew-restart'`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, "renew-restart", 7)
	w := postLeaseRenewal(t, s, priv, "renew-restart", 7, 3600)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-restart renewal status=%d body=%s", w.Code, w.Body.String())
	}
	var first struct {
		ExpiresAt string `json:"lease_expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	// Reopening the relay retains the SQLite expiry and audit record but
	// starts with an empty in-memory session registry. A legitimate new
	// attachment fences the old generation, then renews under generation 8.
	s2, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	var persisted string
	if err := db.SQL().QueryRow(`SELECT expires_at FROM leases WHERE id='renew-restart'`).Scan(&persisted); err != nil || persisted != first.ExpiresAt {
		t.Fatalf("persisted expiry=%q want=%q err=%v", persisted, first.ExpiresAt, err)
	}
	if _, err := db.SQL().Exec(`UPDATE leases SET status='ACTIVE', generation=8, reconnect_until=NULL WHERE id='renew-restart'`); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s2, "renew-restart", 8)
	w = postLeaseRenewal(t, s2, priv, "renew-restart", 8, 3600)
	if w.Code != http.StatusOK {
		t.Fatalf("post-restart renewal status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestLeaseRenewalRevocationRaceLeavesRevocationAuthoritative(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "renew-key", "tenant-test")
	insertLeaseRow(t, db, "renew-race", "ACTIVE", 7, nil)
	if _, err := db.SQL().Exec(`UPDATE leases SET agent_key_id='renew-key', expires_at=? WHERE id='renew-race'`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, "renew-race", 7)
	started := make(chan struct{})
	results := make(chan int, 2)
	go func() {
		close(started)
		w := postLeaseRenewal(t, s, priv, "renew-race", 7, 3600)
		results <- w.Code
	}()
	<-started
	go func() {
		r := signedMgmtRequest(t, priv, "renew-key", http.MethodPost, "/v1/agent/lease/renew-race/revoke")
		w := httptest.NewRecorder()
		s.handleAgentLease(w, r)
		results <- w.Code
	}()
	<-results
	<-results
	var state string
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id='renew-race'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "REVOKED" {
		t.Fatalf("renew/revoke race ended in %s, want REVOKED", state)
	}
}

func TestAdmissionExpiryCASDoesNotEvictConcurrentRenewal(t *testing.T) {
	s, db := newLifecycleServer(t)
	insertLeaseRow(t, db, "expiry-cas", lease.StateActive, 7, nil)
	oldExpiry := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := db.SQL().Exec(`UPDATE leases SET expires_at=? WHERE id='expiry-cas'`, oldExpiry); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, "expiry-cas", 7)
	sess, ok := s.liveSession("expiry-cas")
	if !ok {
		t.Fatal("fabricated session not live")
	}
	newExpiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	s.leaseExpiryCASHook = func(id string) {
		if id != "expiry-cas" {
			t.Errorf("expiry hook lease=%q", id)
		}
		if _, err := db.SQL().Exec(`UPDATE leases SET expires_at=? WHERE id=?`, newExpiry, id); err != nil {
			t.Errorf("simulate concurrent renewal: %v", err)
		}
	}
	target := &routeTarget{LeaseID: "expiry-cas", Generation: 7, AccessMode: "protected"}
	got, admittedSession, code := s.admitRoutedLease(target, lease.StateActive, sql.NullString{String: oldExpiry, Valid: true})
	if code != 0 || got == nil || admittedSession != sess || !got.ExpiresAt.After(time.Now()) {
		t.Fatalf("renewed row rejected or evicted: target=%+v session=%p want=%p code=%d", got, admittedSession, sess, code)
	}
	var state string
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id='expiry-cas'`).Scan(&state); err != nil || state != lease.StateActive {
		t.Fatalf("concurrent renewal state=%q err=%v", state, err)
	}
}

func TestLeaseStatusReportsExpiryAndRenewal(t *testing.T) {
	s, db := newLifecycleServer(t)
	priv := enrollTestKey(t, db.SQL(), "renew-key", "tenant-test")
	insertLeaseRow(t, db, "renew-status", "ACTIVE", 2, nil)
	exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if _, err := db.SQL().Exec(`UPDATE leases SET agent_key_id='renew-key', expires_at=? WHERE id='renew-status'`, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO audit_events(time,actor,tenant_id,lease_id,category,result,detail) VALUES(?,?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339Nano), "agent", "tenant-test", "renew-status", "lease-renew", "ok", exp); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleAgentLease(w, signedMgmtRequest(t, priv, "renew-key", http.MethodGet, "/v1/agent/lease/renew-status/status"))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["lease_expires_at"] != exp || !strings.HasPrefix(got["last_renewal_result"].(string), "ok:") || got["last_renewal_at"] == "" || got["route_available"] != false {
		t.Fatalf("status renewal fields = %#v", got)
	}
}
