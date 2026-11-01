// P0-A: operator key revocation terminates forwarding authority, not
// just future authentication. A revoked key cannot challenge, connect,
// resume, allocate, create routes, or keep a live session forwarding;
// tenant suspension denies the whole tenant the same way.
package relay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ocliv/internal/lease"
)

// postChallenge drives the mux-level challenge endpoint as a loopback
// peer (the trusted-edge hop), proving the HTTP-visible verdict for a
// key: 200 issues a nonce, 401 denies without one.
func postChallengeCode(t *testing.T, s *Server, keyID string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/agent/challenge",
		strings.NewReader(fmt.Sprintf(`{"key_id":%q}`, keyID)))
	r.Host = "relay.example.test"
	r.RemoteAddr = "127.0.0.1:5000"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}

// TestRevokeAgentKeyTerminatesAuthority drives the full revocation
// contract at the Server boundary: durable state flips terminally, the
// live session is evicted, and every later attach path is denied.
func TestRevokeAgentKeyTerminatesAuthority(t *testing.T) {
	s, db := newLifecycleServer(t)
	enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	ls, _, err := s.allocateOrResume("tenant-test", "key-test", LeaseIntent{
		Port: 3000, Ready: true, Version: "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, ls.ID, 1)
	if _, live := s.liveSession(ls.ID); !live {
		t.Fatal("setup has no live session")
	}
	affected, err := s.RevokeAgentKey("key-test", "operator-test")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(affected) != 1 || affected[0] != ls.ID {
		t.Fatalf("revoked leases=%v, want [%s]", affected, ls.ID)
	}
	if _, live := s.liveSession(ls.ID); live {
		t.Fatal("revoked lease still has a live session")
	}
	var kst, lst string
	if err := db.SQL().QueryRow(`SELECT status FROM agent_keys WHERE id='key-test'`).Scan(&kst); err != nil || kst != "revoked" {
		t.Fatalf("key status=%q err=%v", kst, err)
	}
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, ls.ID).Scan(&lst); err != nil || lst != "REVOKED" {
		t.Fatalf("lease status=%q err=%v", lst, err)
	}
	// Resume with the revoked key is denied, not fenced into a new lease.
	if _, _, err := s.allocateOrResume("tenant-test", "key-test", LeaseIntent{
		Port: 3000, Ready: true, Version: "1", LeaseID: ls.ID,
	}); err == nil {
		t.Fatal("revoked key resumed its lease")
	}
	// Fresh allocation with the revoked key is denied too.
	if _, _, err := s.allocateOrResume("tenant-test", "key-test", LeaseIntent{
		Port: 3001, Ready: true, Version: "1",
	}); err == nil {
		t.Fatal("revoked key allocated a new lease")
	}
	// Unknown keys stay unknown (no oracle change).
	if _, err := s.RevokeAgentKey("key-nope", "operator-test"); err == nil {
		t.Fatal("revoking an unknown key succeeded")
	}
}

// TestRevokedKeyDeniedChallengeAtEdge: the HTTP-visible challenge
// verdict flips from 200 to 401 on revocation — a revoked publisher
// cannot even begin a handshake.
func TestRevokedKeyDeniedChallengeAtEdge(t *testing.T) {
	s, _ := newLifecycleServer(t)
	enrollTestKey(t, s.db.SQL(), "key-test", "tenant-test")
	if code := postChallengeCode(t, s, "key-test"); code != http.StatusOK {
		t.Fatalf("active key challenge: status=%d, want 200", code)
	}
	if _, err := s.RevokeAgentKey("key-test", "operator-test"); err != nil {
		t.Fatal(err)
	}
	if code := postChallengeCode(t, s, "key-test"); code != http.StatusUnauthorized {
		t.Fatalf("revoked key challenge: status=%d, want 401", code)
	}
}

// TestSuspendedTenantDeniedChallengeAtEdge: suspending a tenant denies
// challenge for its (revoked) keys at the edge.
func TestSuspendedTenantDeniedChallengeAtEdge(t *testing.T) {
	s, _ := newLifecycleServer(t)
	enrollTestKey(t, s.db.SQL(), "key-test", "tenant-test")
	if code := postChallengeCode(t, s, "key-test"); code != http.StatusOK {
		t.Fatalf("active key challenge: status=%d, want 200", code)
	}
	if err := s.SuspendTenant("tenant-test", "operator-test"); err != nil {
		t.Fatal(err)
	}
	if code := postChallengeCode(t, s, "key-test"); code != http.StatusUnauthorized {
		t.Fatalf("suspended tenant challenge: status=%d, want 401", code)
	}
}

// TestRevokeDeniesLiveDispatchAtBoundary: a published route admitted
// against a live session is denied at the dispatch boundary after key
// revocation — the session is evicted and the revoked publication can
// never serve again.
func TestRevokeDeniesLiveDispatchAtBoundary(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-live", "lived.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-live", "upstream-oauth")
	liveFabricatedSession(t, s, "lse-live", 1)
	if _, _, _, code := s.resolveMCPRouteID(r1); code != 0 {
		t.Fatalf("live route denied before revoke: code=%d", code)
	}
	if _, err := s.RevokeAgentKey("key-test", "operator-test"); err != nil {
		t.Fatal(err)
	}
	if _, live := s.liveSession("lse-live"); live {
		t.Fatal("revoked lease still has a live session")
	}
	if _, _, _, code := s.resolveMCPRouteID(r1); code != http.StatusNotFound {
		t.Fatalf("revoked route admitted after revoke: code=%d, want 404", code)
	}
}

// TestSuspendTenantDeniesAllocate: suspending a tenant revokes its
// leases and denies later attach paths even for keys that were active.
func TestSuspendTenantDeniesAllocate(t *testing.T) {
	s, db := newLifecycleServer(t)
	enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	if _, _, err := s.allocateOrResume("tenant-test", "key-test", LeaseIntent{
		Port: 3000, Ready: true, Version: "1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SuspendTenant("tenant-test", "operator-test"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	var tst string
	if err := db.SQL().QueryRow(`SELECT status FROM tenants WHERE id='tenant-test'`).Scan(&tst); err != nil || tst != "suspended" {
		t.Fatalf("tenant status=%q err=%v", tst, err)
	}
	if _, _, err := s.allocateOrResume("tenant-test", "key-test", LeaseIntent{
		Port: 3001, Ready: true, Version: "1",
	}); err == nil {
		t.Fatal("suspended tenant allocated a lease")
	}
}
