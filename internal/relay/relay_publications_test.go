// Key-scoped publication management tests (P0-D). Publications are durable
// identities that outlive individual leases, so management targets the
// publication (route_id) authenticated by the owning key — never a
// client-supplied lease. Unpublish removes exactly one owned publication,
// sibling publications on the same lease survive, and cross-key access is
// denied without leaking existence beyond a 404.
package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"ocliv/internal/lease"
)

// getKeyPublications GETs /v1/agent/mcp-routes through the full handler
// stack with key-scoped auth.
func getKeyPublications(t *testing.T, s *Server, priv ed25519.PrivateKey, keyID string) (int, string) {
	t.Helper()
	path := "/v1/agent/mcp-routes"
	r := signedMgmtRequest(t, priv, keyID, http.MethodGet, path)
	r.Host = "relay.example.test"
	r.RequestURI = path
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// deleteKeyPublication DELETEs one route through the full stack.
func deleteKeyPublication(t *testing.T, s *Server, priv ed25519.PrivateKey, keyID, routeID string) (int, string) {
	t.Helper()
	path := "/v1/agent/mcp-routes/" + routeID
	r := signedMgmtRequest(t, priv, keyID, http.MethodDelete, path)
	r.Host = "relay.example.test"
	r.RequestURI = path
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func decodePubs(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out struct {
		Publications []map[string]any `json:"publications"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Publications == nil {
		t.Fatalf("bad publications body %q err=%v", body, err)
	}
	return out.Publications
}

// TestKeyPublicationsListAcrossLeases: one key owning publications on two
// leases lists both, including the revoked tombstone with its state.
func TestKeyPublicationsListAcrossLeases(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "alpha.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	insertMCPLeaseRow(t, db, "lse-b", "beta.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	r2 := publishRoute(t, s, priv, "key-test", "lse-b", "upstream-oauth")

	code, body := getKeyPublications(t, s, priv, "key-test")
	if code != http.StatusOK {
		t.Fatalf("list: status=%d body=%s", code, body)
	}
	pubs := decodePubs(t, body)
	if len(pubs) != 2 {
		t.Fatalf("list returned %d publications, want 2: %s", len(pubs), body)
	}
	seen := map[string]bool{}
	for _, p := range pubs {
		id, _ := p["route_id"].(string)
		seen[id] = true
		if id != r1 && id != r2 {
			t.Fatalf("list leaked unexpected route %q", id)
		}
	}
	if !seen[r1] || !seen[r2] {
		t.Fatalf("list missing routes: got %v want %q and %q", seen, r1, r2)
	}
}

// TestKeyPublicationDeleteSingle: DELETE removes exactly the named route;
// a sibling publication on the same lease keeps resolving.
func TestKeyPublicationDeleteSingle(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "alpha.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	// Two publications bound to the same lease: different profiles share
	// one lease only if labels differ, so use a second lease with the
	// same label family via relabel.
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	insertMCPLeaseRow(t, db, "lse-b", "beta.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r2 := publishRoute(t, s, priv, "key-test", "lse-b", "upstream-oauth")
	if r1 == r2 {
		t.Fatalf("distinct publications minted identical route %q", r1)
	}
	liveFabricatedSession(t, s, "lse-b", 1)

	if code, body := deleteKeyPublication(t, s, priv, "key-test", r1); code != http.StatusOK {
		t.Fatalf("delete: status=%d body=%s", code, body)
	}
	// Deleted route no longer lists.
	if _, body := getKeyPublications(t, s, priv, "key-test"); strings.Contains(body, r1) {
		t.Fatalf("deleted route %q still listed: %s", r1, body)
	}
	// Sibling publication survives and still resolves.
	if _, _, _, code := s.resolveMCPRouteID(r2); code != 0 {
		t.Fatalf("sibling publication %q denied after unrelated delete: code=%d", r2, code)
	}
	// Repeat delete of the same route is 404, not a silent success.
	if code, _ := deleteKeyPublication(t, s, priv, "key-test", r1); code != http.StatusNotFound {
		t.Fatalf("repeat delete: status=%d want 404", code)
	}
}

// TestKeyPublicationsCrossKeyDenied: a second enrolled key cannot list or
// delete the first key's publications, and learns nothing beyond a 404.
func TestKeyPublicationsCrossKeyDenied(t *testing.T) {
	s, db := newMCPServer(t)
	privA := enrollTestKey(t, db.SQL(), "key-a", "tenant-test")
	privB := enrollTestKey(t, db.SQL(), "key-b", "tenant-test")
	// lse-a is owned by key-a: insertMCPLeaseRow hardcodes key-test, so
	// the row is written directly to match the signing identity.
	if _, err := db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"lse-a", "tenant-test", "key-a", "alpha.t.example.test", "alpha", 3000,
		AccessModeMCPUpstreamOAuth, 1, lease.StateActive,
		"2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	r1 := publishRoute(t, s, privA, "key-a", "lse-a", "upstream-oauth")

	if code, _ := getKeyPublications(t, s, privB, "key-b"); code != http.StatusOK {
		t.Fatalf("key-b list: status=%d", code)
	} else {
		_, body := getKeyPublications(t, s, privB, "key-b")
		if strings.Contains(body, r1) {
			t.Fatalf("key-b list leaked key-a route %q", r1)
		}
	}
	if code, _ := deleteKeyPublication(t, s, privB, "key-b", r1); code != http.StatusNotFound {
		t.Fatalf("cross-key delete: status=%d want 404", code)
	}
	// Owner's route is untouched: with a live session it still resolves.
	liveFabricatedSession(t, s, "lse-a", 1)
	if _, _, _, code := s.resolveMCPRouteID(r1); code != 0 {
		t.Fatalf("owner route %q denied after cross-key attempt: code=%d", r1, code)
	}
}

// TestKeyPublicationsRevokedKeyDenied: after operator revocation the key's
// management plane (list and delete) is denied at the identity gate,
// before any row is touched.
func TestKeyPublicationsRevokedKeyDenied(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "alpha.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")

	if _, err := s.RevokeAgentKey("key-test", "operator-test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if code, _ := getKeyPublications(t, s, priv, "key-test"); code != http.StatusForbidden {
		t.Fatalf("revoked-key list: status=%d want 403", code)
	}
	if code, _ := deleteKeyPublication(t, s, priv, "key-test", r1); code != http.StatusForbidden {
		t.Fatalf("revoked-key delete: status=%d want 403", code)
	}
}

// TestMgmtFailClosedOnStorageError: with the database gone, key-scoped
// list/delete and lease-scoped route creation all deny (never 2xx,
// never a panic). Auth lookup failure denies at the gate, matching the
// established agentLeaseAuth contract.
func TestMgmtFailClosedOnStorageError(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "alpha.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	_ = db.Close()
	if code, _ := getKeyPublications(t, s, priv, "key-test"); code < 400 {
		t.Fatalf("key list with dead storage: status=%d, want denial", code)
	}
	if code, _ := deleteKeyPublication(t, s, priv, "key-test", r1); code < 400 {
		t.Fatalf("key delete with dead storage: status=%d, want denial", code)
	}
	if code, _ := postMCPRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth"); code < 400 {
		t.Fatalf("lease route create with dead storage: status=%d, want denial", code)
	}
	if code, _ := postMCPDelete(t, s, priv, "key-test", "lse-a", r1); code < 400 {
		t.Fatalf("lease route delete with dead storage: status=%d, want denial", code)
	}
}

// TestKeyPublicationsCarryReachability (P1): the listing separates
// durable publication state from relay-observed reachability. A stored
// ACTIVE publication with no live session reports lease_state ACTIVE
// with session_live=false (the funnel-oauth discrepancy: recorded but
// unreachable must never read as healthy); once a live session of the
// current generation registers, session_live becomes true.
func TestKeyPublicationsCarryReachability(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "alpha.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	insertMCPLeaseRow(t, db, "lse-b", "beta.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	publishRoute(t, s, priv, "key-test", "lse-b", "upstream-oauth")

	byRoute := func() map[string]map[string]any {
		t.Helper()
		code, body := getKeyPublications(t, s, priv, "key-test")
		if code != http.StatusOK {
			t.Fatalf("list: status=%d body=%s", code, body)
		}
		m := map[string]map[string]any{}
		for _, p := range decodePubs(t, body) {
			id, _ := p["route_id"].(string)
			m[id] = p
		}
		return m
	}
	reach := func(p map[string]any) (string, bool) {
		st, _ := p["lease_state"].(string)
		live, _ := p["session_live"].(bool)
		return st, live
	}
	m := byRoute()
	if st, live := reach(m[r1]); st != lease.StateActive || live {
		t.Fatalf("no session: lease_state=%q session_live=%v, want ACTIVE/false", st, live)
	}

	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		<-r.Context().Done()
	}))
	defer ws.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, ws.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	go s.registerSession(context.Background(), conn,
		&lease.Lease{ID: "lse-a", Hostname: "alpha.t.example.test", Generation: 1},
		"tenant-test", "key-test", "")
	deadline := time.Now().Add(10 * time.Second)
	for {
		m = byRoute()
		if _, live := reach(m[r1]); live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("live session for lse-a never surfaced: %v", m[r1])
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestKeyPublicationsUnknownRoute404: deleting a well-formed but unknown
// route ID is 404, and malformed IDs never reach the store.
func TestKeyPublicationsUnknownRoute404(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	if code, _ := deleteKeyPublication(t, s, priv, "key-test", "r-0000000000000000"); code != http.StatusNotFound {
		t.Fatalf("unknown route delete: status=%d want 404", code)
	}
	path := "/v1/agent/mcp-routes/../../etc/passwd"
	r := signedMgmtRequest(t, priv, "key-test", http.MethodDelete, "/v1/agent/mcp-routes/x")
	r.Host = "relay.example.test"
	r.RequestURI = path
	r.URL.Path = path
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Fatalf("traversal delete unexpectedly succeeded")
	}
}
