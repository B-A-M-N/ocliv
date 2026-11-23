package relay

import (
	"net/http"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/lease"
)

// TestUnpublishRetiresRouteApprovals is the failing-first regression for a
// fail-closed gap found by the external qualification: unpublishing a
// managed route deleted the publication but left the operator's approvals
// ACTIVE in the authorization plane (22 active grants and 27 client
// registrations survived a removed route in the staging run).
//
// An approval is authority over a route that no longer exists. Leaving it
// active means a later route reusing the id would silently inherit it, and
// the operator's "authz list" view claims clients are still approved for a
// route that is gone. The runbook's teardown oracle requires the grant row
// to be gone or revoked.
//
// Failing-first: before the fix the grants were still 'active' after the
// delete.
func TestUnpublishRetiresRouteApprovals(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-1", "owner.t.example.test", AccessModeMCPManaged, lease.StateActive, 1, nil)
	route := publishRoute(t, s, priv, "key-test", "lse-1", "managed-oauth")

	// Two operator approvals on that route, one on a different route.
	az := authz.NewSQLStore(db.SQL())
	for _, c := range []struct{ client, r string }{
		{"cli-a", route},
		{"cli-b", route},
		{"cli-c", "other-route"},
	} {
		if err := az.RegisterClient(authz.Client{ID: c.client, Tenant: "tenant-test", Route: c.r}); err != nil {
			t.Fatalf("register client %s: %v", c.client, err)
		}
		if err := az.CreateGrant(authz.Grant{ClientID: c.client, Tenant: "tenant-test", Route: c.r,
			Status: authz.GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
			t.Fatalf("grant %s: %v", c.client, err)
		}
	}

	if code, body := deleteKeyPublication(t, s, priv, "key-test", route); code != http.StatusOK {
		t.Fatalf("delete: status=%d body=%s", code, body)
	}

	// The removed route's approvals must be retired; another route's must
	// not be (the revocation is scoped to tenant + route).
	for _, c := range []struct{ client, r, want string }{
		{"cli-a", route, string(authz.GrantRevoked)},
		{"cli-b", route, string(authz.GrantRevoked)},
		{"cli-c", "other-route", string(authz.GrantActive)},
	} {
		g, err := az.GetGrant(c.client, "tenant-test", c.r)
		if err != nil {
			t.Fatalf("grant %s: %v", c.client, err)
		}
		if string(g.Status) != c.want {
			t.Fatalf("grant %s on route %s status=%q, want %q", c.client, c.r, g.Status, c.want)
		}
	}
}
