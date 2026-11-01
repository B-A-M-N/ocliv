// Durable publication identity tests (P1-A). A publication is a stable
// public route separate from the active tunnel lease: the same
// (tenant, owner key, external host, profile, label) republishes the
// same route_id across replacement leases, restarts, and reclaims,
// while revocation tombstones the route permanently. Every test below
// drives the signed management path (postMCPRoute) or the real
// insertLease reclaim, never raw row writes for the behavior itself.
package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ocliv/internal/lease"
	"ocliv/internal/metrics"
	"ocliv/internal/store"
)

// publishRoute POSTs a route create and returns the minted route ID.
func publishRoute(t *testing.T, s *Server, priv ed25519.PrivateKey, keyID, leaseID, profile string) string {
	t.Helper()
	code, body := postMCPRoute(t, s, priv, keyID, leaseID, profile)
	if code != http.StatusOK {
		t.Fatalf("publish %s/%s: status=%d body=%s", leaseID, profile, code, body)
	}
	var rr struct {
		RouteID string `json:"route_id"`
		URL     string `json:"url"`
	}
	if err := json.Unmarshal([]byte(body), &rr); err != nil || rr.RouteID == "" || rr.URL == "" {
		t.Fatalf("publish %s: bad reply %q err=%v", leaseID, body, err)
	}
	return rr.RouteID
}

// relabel sets a lease's publication label directly, mirroring a
// republish with --name on a fresh lease.
func relabel(t *testing.T, db *store.DB, leaseID, label string) {
	t.Helper()
	if _, err := db.SQL().Exec(`UPDATE leases SET label=? WHERE id=?`, label, leaseID); err != nil {
		t.Fatal(err)
	}
}

// chownLease reassigns a fixture lease's owner key directly. Setup only:
// it stands in for a lease allocated by the named key, since
// insertMCPLeaseRow always writes owner key-test.
func chownLease(t *testing.T, db *store.DB, leaseID, keyID string) {
	t.Helper()
	if _, err := db.SQL().Exec(`UPDATE leases SET agent_key_id=? WHERE id=?`, keyID, leaseID); err != nil {
		t.Fatal(err)
	}
}

// TestPublicationStableAcrossLeases: closing a lease (ordinary
// shutdown) retains the publication; a replacement lease under the
// same name rebinds it and serves the identical public route.
func TestPublicationStableAcrossLeases(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "stable.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	if err := s.closeLeaseDurable("lse-a"); err != nil {
		t.Fatal(err)
	}
	// Offline now: mapping retained, but no live session may forward.
	if w := serveRoute(s, "POST", "public.example.org", "/r/"+r1+"/mcp", nil); w.Code == http.StatusOK {
		t.Fatalf("offline publication forwarded: %d", w.Code)
	}
	insertMCPLeaseRow(t, db, "lse-b", "other.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	relabel(t, db, "lse-b", "stable")
	r2 := publishRoute(t, s, priv, "key-test", "lse-b", "upstream-oauth")
	if r2 != r1 {
		t.Fatalf("replacement lease minted %q, want stable %q", r2, r1)
	}
	var bound string
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id=?`, r1).Scan(&bound); err != nil || bound != "lse-b" {
		t.Fatalf("publication bound to %q err=%v, want lse-b", bound, err)
	}
	liveFabricatedSession(t, s, "lse-b", 1)
	if _, _, _, code := s.resolveMCPRouteID(r1); code != 0 {
		t.Fatalf("rebound publication denied: code=%d", code)
	}
}

// TestPublicationReclaimRebindsAutomatically: a named-lease reclaim
// carries the live publication to the replacement lease in the same
// transaction, so the public URL never changes across restarts.
func TestPublicationReclaimRebindsAutomatically(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	label := "reclaim"
	ls, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPUpstreamOAuth}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	r1 := publishRoute(t, s, priv, "key-test", ls.ID, "upstream-oauth")
	ls2, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPUpstreamOAuth}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	var bound string
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id=?`, r1).Scan(&bound); err != nil || bound != ls2.ID {
		t.Fatalf("reclaim bound publication to %q err=%v, want %s", bound, err, ls2.ID)
	}
	r2 := publishRoute(t, s, priv, "key-test", ls2.ID, "upstream-oauth")
	if r2 != r1 {
		t.Fatalf("post-reclaim publish minted %q, want stable %q", r2, r1)
	}
}

// TestPublicationWrongOwnerIsolated: a different owner publishing the
// same name gets a separate publication (never the victim's route),
// and cannot delete the victim's publication through its own lease.
func TestPublicationWrongOwnerIsolated(t *testing.T) {
	s, db := newMCPServer(t)
	privA := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	privB := enrollTestKey(t, db.SQL(), "key-b", "tenant-b")
	insertMCPLeaseRow(t, db, "lse-a", "shared.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	rA := publishRoute(t, s, privA, "key-test", "lse-a", "upstream-oauth")
	if _, err := db.SQL().Exec(`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		VALUES('lse-b','tenant-b','key-b','shared2.t.example.test','shared',3000,?,1,'ACTIVE',?)`,
		AccessModeMCPUpstreamOAuth, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	rB := publishRoute(t, s, privB, "key-b", "lse-b", "upstream-oauth")
	if rB == rA {
		t.Fatal("cross-owner publish returned the victim's route")
	}
	// Owner B cannot delete owner A's publication via its own lease.
	dcode, _ := postMCPDelete(t, s, privB, "key-b", "lse-b", rA)
	if dcode != http.StatusNotFound {
		t.Fatalf("cross-owner delete: status=%d, want 404", dcode)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications WHERE route_id=?`, rA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("victim publication disturbed: n=%d err=%v", n, err)
	}
}

// TestPublicationProfileDowngradeRejected: the same owner/host/name
// with a different profile is an explicit-replacement situation,
// never an implicit authorization downgrade under a stable URL.
func TestPublicationProfileDowngradeRejected(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "prof.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	insertMCPLeaseRow(t, db, "lse-f", "other.t.example.test", AccessModeMCPAnonymousFixture, lease.StateActive, 1, nil)
	relabel(t, db, "lse-f", "prof")
	if code, body := postMCPRoute(t, s, priv, "key-test", "lse-f", "fixture-anonymous"); code != http.StatusConflict {
		t.Fatalf("profile downgrade: status=%d body=%s, want 409", code, body)
	}
}

// TestPublicationRevokedPermanentlyDenied: revoking a lease tombstones
// its publication — admission denies, and no rebind under any lease
// revives the route. A fresh name still works.
func TestPublicationRevokedPermanentlyDenied(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "doomed.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	if err := s.revokeLease("lse-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, code := s.resolveMCPRouteID(r1); code != http.StatusNotFound {
		t.Fatalf("revoked publication admitted: code=%d", code)
	}
	insertMCPLeaseRow(t, db, "lse-b", "other.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	relabel(t, db, "lse-b", "doomed")
	if code, _ := postMCPRoute(t, s, priv, "key-test", "lse-b", "upstream-oauth"); code != http.StatusConflict {
		t.Fatalf("rebind of revoked publication: status=%d, want 409", code)
	}
	insertMCPLeaseRow(t, db, "lse-c", "fresh.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	if r2 := publishRoute(t, s, priv, "key-test", "lse-c", "upstream-oauth"); r2 == r1 {
		t.Fatal("fresh name reused the revoked route")
	}
}

// TestNamedLeaseReclaimWithRevokedPublication (P0-B): a named-lease
// reclaim must succeed even when a revoked publication tombstone still
// references the retired lease. The tombstone keeps its immutable route
// identity and revoked state, independent of the deleted lease record;
// live-publication reclaim/rebind is unaffected.
func TestNamedLeaseReclaimWithRevokedPublication(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	label := "doomed-reclaim"
	ls, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPUpstreamOAuth}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	r1 := publishRoute(t, s, priv, "key-test", ls.ID, "upstream-oauth")
	if err := s.revokeLease(ls.ID); err != nil {
		t.Fatal(err)
	}
	// The reclaim itself is the assertion: the deferred
	// mcp_publications FK must not reject the commit that retires the
	// revoked lease.
	ls2, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPUpstreamOAuth}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("named reclaim with revoked tombstone failed: %v", err)
	}
	// Tombstone preserved: same name+profile stays denied, route never serves.
	if code, _ := postMCPRoute(t, s, priv, "key-test", ls2.ID, "upstream-oauth"); code != http.StatusConflict {
		t.Fatalf("rebind of revoked publication: status=%d, want 409", code)
	}
	var got string
	var revokedAt *string
	if err := db.SQL().QueryRow(`SELECT route_id, revoked_at FROM mcp_publications WHERE route_id=?`, r1).Scan(&got, &revokedAt); err != nil || got != r1 || revokedAt == nil {
		t.Fatalf("tombstone lost: route=%q revoked=%v err=%v", got, revokedAt, err)
	}
	if _, _, _, code := s.resolveMCPRouteID(r1); code != http.StatusNotFound {
		t.Fatalf("revoked publication admitted after reclaim: code=%d", code)
	}
}

// TestPublicationRepeatedPublishSameLease: republishing under the same
// live lease returns the identical route (P0-B qual): no duplicate
// rows, no new public URL.
func TestPublicationRepeatedPublishSameLease(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "same.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	r2 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	if r2 != r1 {
		t.Fatalf("same-lease republish minted %q, want stable %q", r2, r1)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("publication rows=%d err=%v, want exactly 1", n, err)
	}
}

// TestPublicationDenialsCounted: revoked, offline, and unknown route
// resolutions each emit exactly one bounded admission rejection;
// a successful admission emits none (P1-D metrics).
func TestPublicationDenialsCounted(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "counted.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	before := metrics.Global.MCPAdmissionRejects.Load()
	if _, _, _, code := s.resolveMCPRouteID("route-does-not-exist"); code != http.StatusNotFound {
		t.Fatalf("unknown route: code=%d, want 404", code)
	}
	if err := s.closeLeaseDurable("lse-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, code := s.resolveMCPRouteID(r1); code != http.StatusServiceUnavailable {
		t.Fatalf("offline route: code=%d, want 503", code)
	}
	if got := metrics.Global.MCPAdmissionRejects.Load() - before; got != 2 {
		t.Fatalf("denial counter delta=%d, want 2", got)
	}
	// Reopen to prove a successful admission emits nothing.
	if _, err := db.SQL().Exec(`UPDATE leases SET status=? WHERE id=?`, lease.StateActive, "lse-a"); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s, "lse-a", 1)
	before = metrics.Global.MCPAdmissionRejects.Load()
	if _, _, _, code := s.resolveMCPRouteID(r1); code != 0 {
		t.Fatalf("admit after resume: code=%d", code)
	}
	if got := metrics.Global.MCPAdmissionRejects.Load() - before; got != 0 {
		t.Fatalf("success emitted %d rejections, want 0", got)
	}
}

// TestPublicationStaleLeaseCannotRebind: a CLOSED lease cannot
// (re)publish — the create fails 409 and the binding is untouched.
func TestPublicationStaleLeaseCannotRebind(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "stale.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	if err := s.closeLeaseDurable("lse-a"); err != nil {
		t.Fatal(err)
	}
	if code, _ := postMCPRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth"); code != http.StatusConflict {
		t.Fatalf("closed-lease publish: status=%d, want 409", code)
	}
	var bound string
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id=?`, r1).Scan(&bound); err != nil || bound != "lse-a" {
		t.Fatalf("stale publish moved binding to %q err=%v", bound, err)
	}
}

// TestPublicationConcurrentRebindConverges: concurrent publishes from
// two live same-name leases converge on one route row; every caller
// gets the same stable URL and the binding is exactly one lease.
func TestPublicationConcurrentRebindConverges(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "race.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	insertMCPLeaseRow(t, db, "lse-b", "race2.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	relabel(t, db, "lse-b", "race")
	const callers = 8
	ids := make([]string, callers)
	codes := make([]int, callers)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lid := "lse-a"
			if i%2 == 1 {
				lid = "lse-b"
			}
			code, body := postMCPRoute(t, s, priv, "key-test", lid, "upstream-oauth")
			codes[i] = code
			if code == http.StatusOK {
				var rr struct {
					RouteID string `json:"route_id"`
				}
				_ = json.Unmarshal([]byte(body), &rr)
				ids[i] = rr.RouteID
			}
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("caller %d: status=%d, want 200", i, c)
		}
		if ids[i] != ids[0] {
			t.Fatalf("caller %d got %q, want stable %q", i, ids[i], ids[0])
		}
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications WHERE pub_name='race'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("publication rows=%d err=%v, want exactly 1", n, err)
	}
}

// TestPublicationSurvivesRelayRestart: the publication is durable
// SQLite state — a fresh Server over the same database admits the
// route against a live session without republishing.
func TestPublicationSurvivesRelayRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ocliv.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test", MCPExternalHost: "public.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "persist.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	code, body := postMCPRoute(t, s, priv, "key-test", "lse-a", "upstream-oauth")
	if code != http.StatusOK {
		t.Fatalf("publish: status=%d body=%s", code, body)
	}
	var rr struct {
		RouteID string `json:"route_id"`
	}
	if err := json.Unmarshal([]byte(body), &rr); err != nil || rr.RouteID == "" {
		t.Fatalf("bad publish reply %q", body)
	}
	_ = db.Close()
	db2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	s2, err := New(Options{DB: db2, Namespace: "t.example.test", RelayHost: "relay.example.test", MCPExternalHost: "public.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	// A fresh boot parks previously ACTIVE leases in RECONNECTING
	// (no live session yet): the retained publication must deny as
	// offline (503), never as unknown, and never forward.
	if _, _, _, code := s2.resolveMCPRouteID(rr.RouteID); code != http.StatusServiceUnavailable {
		t.Fatalf("post-restart offline resolve: code=%d, want 503", code)
	}
	// Simulated resume: the agent reconnects, the lease returns to
	// ACTIVE, and the same route admits without republishing.
	if _, err := db2.SQL().Exec(`UPDATE leases SET status=? WHERE id=?`, lease.StateActive, "lse-a"); err != nil {
		t.Fatal(err)
	}
	liveFabricatedSession(t, s2, "lse-a", 1)
	tgt, _, _, code := s2.resolveMCPRouteID(rr.RouteID)
	if code != 0 {
		t.Fatalf("post-resume resolve: code=%d", code)
	}
	if tgt.LeaseID != "lse-a" {
		t.Fatalf("post-restart binding: %+v", tgt)
	}
}

// TestReplacementKeyOwnsNothing: revoking a key and re-enrolling a fresh
// key in the same tenant transfers no publications (P0-D fail-closed
// rotation). The new key lists nothing, cannot delete the old tombstoned
// route, and publishing under it mints a distinct route instead of
// reviving or hijacking the old one.
func TestReplacementKeyOwnsNothing(t *testing.T) {
	s, db := newMCPServer(t)
	privOld := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-old", "rot.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, privOld, "key-test", "lse-old", "upstream-oauth")
	if _, err := s.RevokeAgentKey("key-test", "operator-test"); err != nil {
		t.Fatal(err)
	}
	privNew := enrollTestKey(t, db.SQL(), "key-new", "tenant-test")
	if code, body := getKeyPublications(t, s, privNew, "key-new"); code != http.StatusOK {
		t.Fatalf("new key list: status=%d body=%s, want 200", code, body)
	} else if pubs := decodePubs(t, body); len(pubs) != 0 {
		t.Fatalf("new key lists %d publications, want 0", len(pubs))
	}
	if code, _ := deleteKeyPublication(t, s, privNew, "key-new", r1); code != http.StatusNotFound {
		t.Fatalf("new key delete of old route: status=%d, want 404", code)
	}
	var rev string
	if err := db.SQL().QueryRow(`SELECT COALESCE(revoked_at,'') FROM mcp_publications WHERE route_id=?`, r1).Scan(&rev); err != nil || rev == "" {
		t.Fatalf("old route tombstone lost: revoked_at=%q err=%v", rev, err)
	}
	insertMCPLeaseRow(t, db, "lse-new", "fresh.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	chownLease(t, db, "lse-new", "key-new")
	r2 := publishRoute(t, s, privNew, "key-new", "lse-new", "upstream-oauth")
	if r2 == r1 {
		t.Fatalf("new key inherited old route id %q", r1)
	}
}
