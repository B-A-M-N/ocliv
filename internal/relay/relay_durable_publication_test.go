package relay

// P1: a durable publication identity must survive a publisher restart.
//
// The CLI now derives a publication name from the SERVICE it publishes, so
// the same configured service maps to the same name on every run. The
// relay's job is to make that name mean one stable route: republishing
// under the same (tenant, owner key, host, profile, name) must rebind the
// SAME route id, across a fresh lease and across a reclaim.
//
// This is the relay half of the durable-URL guarantee: the CLI derives
// the name, the relay keeps the identity. The existing publication tests
// cover the upstream-oauth profile; these cover the MANAGED profile (the
// one-command path the product leads with) and the ownership boundary
// for a derived name.
import (
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/lease"
)

// TestManagedPublicationStableAcrossLeases: the managed profile keeps ONE
// route id for one name across a publisher restart, and the publication
// follows the replacement lease.
func TestManagedPublicationStableAcrossLeases(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-m1", "m1.t.example.test", AccessModeMCPManaged, lease.StateActive, 1, nil)
	relabel(t, db, "lse-m1", "mcp-8765-managed-abc12345")
	r1 := publishRoute(t, s, priv, "key-test", "lse-m1", ingressProfileManaged)

	insertMCPLeaseRow(t, db, "lse-m2", "m2.t.example.test", AccessModeMCPManaged, lease.StateActive, 1, nil)
	relabel(t, db, "lse-m2", "mcp-8765-managed-abc12345")
	r2 := publishRoute(t, s, priv, "key-test", "lse-m2", ingressProfileManaged)
	if r2 != r1 {
		t.Fatalf("the same managed name under a replacement lease produced a new route: %q then %q", r1, r2)
	}
	var bound string
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id=?`, r1).Scan(&bound); err != nil || bound != "lse-m2" {
		t.Fatalf("managed publication bound to %q err=%v, want lse-m2", bound, err)
	}
	// Exactly ONE publication row for that name: a restart must not
	// leave an orphan route behind.
	var n int
	if err := db.SQL().QueryRow(
		`SELECT COUNT(1) FROM mcp_publications WHERE tenant_id='tenant-test' AND owner_key_id='key-test' AND pub_name='mcp-8765-managed-abc12345'`,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the durable managed name has %d publication rows, want 1", n)
	}
}

// TestManagedReclaimKeepsRouteID: the same-key reclaim of a managed
// publication's hostname carries the publication to the replacement lease
// and keeps the route id, so the public URL survives a restart.
func TestManagedReclaimKeepsRouteID(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	label := "mcp-8765-managed-reclaim"
	ls, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPManaged}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("first lease: %v", err)
	}
	r1 := publishRoute(t, s, priv, "key-test", ls.ID, ingressProfileManaged)

	ls2, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPManaged}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if ls2.ID == ls.ID {
		t.Fatal("the reclaim reused the retired lease id")
	}
	var bound string
	if err := db.SQL().QueryRow(`SELECT lease_id FROM mcp_publications WHERE route_id=?`, r1).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if bound != ls2.ID {
		t.Fatalf("the publication stayed on the retired lease %q, want %q", bound, ls2.ID)
	}
	r2 := publishRoute(t, s, priv, "key-test", ls2.ID, ingressProfileManaged)
	if r1 != r2 {
		t.Fatalf("the managed reclaim changed the route id: %q then %q", r1, r2)
	}
}

// TestManagedCrossKeyReclaimDoesNotStealThePublication: the ownership
// boundary must hold for the durable managed name too — a second key
// cannot take over the first key's publication.
func TestManagedCrossKeyReclaimDoesNotStealThePublication(t *testing.T) {
	s, db := newMCPServer(t)
	priv1 := enrollTestKey(t, db.SQL(), "key-owner", "tenant-test")
	label := "mcp-8765-managed-owned"
	ls, _, err := s.insertLease("tenant-test", "key-owner", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPManaged}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatalf("first lease: %v", err)
	}
	r1 := publishRoute(t, s, priv1, "key-owner", ls.ID, ingressProfileManaged)

	// A second key in the SAME tenant tries the same name.
	enrollTestKey(t, db.SQL(), "key-other", "tenant-test")
	if _, _, err := s.insertLease("tenant-test", "key-other", label,
		LeaseIntent{Port: 3000, AccessMode: AccessModeMCPManaged}, time.Now().UTC(), &label); err == nil {
		t.Fatal("a foreign key reclaimed a durable managed publication's hostname")
	}
	var owner, bound string
	if err := db.SQL().QueryRow(
		`SELECT owner_key_id, lease_id FROM mcp_publications WHERE route_id=?`, r1).Scan(&owner, &bound); err != nil {
		t.Fatal(err)
	}
	if owner != "key-owner" || bound != ls.ID {
		t.Fatalf("the refused takeover disturbed the publication: owner=%q lease=%q", owner, bound)
	}
}
