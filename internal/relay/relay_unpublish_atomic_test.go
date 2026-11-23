package relay

// C: unpublishing a route and retiring its operator approvals must be one
// transaction. The old sequence deleted the publication, then revoked the
// route's grants, then reported success regardless of the revocation
// outcome — so a failed cleanup could leave a route-less publication while
// the CLI printed success.

import (
	"net/http"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/authz"
)

// The atomic delete must roll BOTH halves when the retirement fails: the
// publication survives and the caller is told it failed, never a partial
// success.
func TestUnpublishRollsBackWhenRetirementFails(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-x", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	route := publishRoute(t, s, priv, "key-test", "lse-x", "managed-oauth")

	az := authz.NewSQLStore(db.SQL())
	if err := az.RegisterClient(authz.Client{ID: "cli-x", Tenant: "tenant-test", Route: route}); err != nil {
		t.Fatal(err)
	}
	if err := az.CreateGrant(authz.Grant{ClientID: "cli-x", Tenant: "tenant-test", Route: route,
		Status: authz.GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// Injected failure: the approval table is gone, so the retirement
	// statement inside the atomic delete cannot succeed. A test-local
	// schema sabotage stands in for any persistence fault mid-transaction.
	if _, err := db.SQL().Exec(`DROP TABLE authz_grants`); err != nil {
		t.Fatal(err)
	}

	if code, body := deleteKeyPublication(t, s, priv, "key-test", route); code != http.StatusInternalServerError {
		t.Fatalf("atomic delete under retirement failure: status=%d body=%s, want 500", code, body)
	}

	// Nothing half-committed: the publication row is still there.
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(1) FROM mcp_publications WHERE route_id=?`, route).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("publication was deleted despite the failed approval retirement (partial commit)")
	}
}

// The happy path stays exactly as before: delete retires the route's
// approvals, scoped to the route.
func TestUnpublishAtomicSuccessPath(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-ok", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	route := publishRoute(t, s, priv, "key-test", "lse-ok", "managed-oauth")

	az := authz.NewSQLStore(db.SQL())
	for _, c := range []struct{ client, r string }{{"cli-ok", route}, {"cli-other", "another-route"}} {
		if err := az.RegisterClient(authz.Client{ID: c.client, Tenant: "tenant-test", Route: c.r}); err != nil {
			t.Fatalf("register client %s: %v", c.client, err)
		}
		if err := az.CreateGrant(authz.Grant{ClientID: c.client, Tenant: "tenant-test", Route: c.r,
			Status: authz.GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := deleteKeyPublication(t, s, priv, "key-test", route); code != http.StatusOK {
		t.Fatalf("atomic delete: status=%d body=%s", code, body)
	}
	var pubN int
	if err := db.SQL().QueryRow(`SELECT COUNT(1) FROM mcp_publications WHERE route_id=?`, route).Scan(&pubN); err != nil {
		t.Fatal(err)
	}
	if pubN != 0 {
		t.Fatal("publication survived a successful delete")
	}
	g, err := az.GetGrant("cli-ok", "tenant-test", route)
	if err != nil || g.Status != authz.GrantRevoked {
		t.Fatalf("route approvals not retired: %+v err=%v", g, err)
	}
	g2, err := az.GetGrant("cli-other", "tenant-test", "another-route")
	if err != nil || g2.Status != authz.GrantActive {
		t.Fatalf("unrelated route's approval touched: %+v err=%v", g2, err)
	}
}

// A foreign key's delete is still the non-disclosing 404, and it must not
// commit anything either.
func TestUnpublishAtomicForeignKeyStill404(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	other := enrollTestKey(t, db.SQL(), "key-other", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-f", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	route := publishRoute(t, s, priv, "key-test", "lse-f", "managed-oauth")

	if code, _ := deleteKeyPublication(t, s, other, "key-other", route); code != http.StatusNotFound {
		t.Fatalf("foreign delete: status=%d, want 404 (non-disclosing)", code)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(1) FROM mcp_publications WHERE route_id=?`, route).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("foreign delete removed the publication")
	}
}
