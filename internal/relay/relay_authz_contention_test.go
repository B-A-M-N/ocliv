package relay

// Priority 1 B: the public OAuth endpoints are rate limited per tenant +
// endpoint KIND + ROUTE. A flood against one route's public endpoint must
// not deny a legitimate caller on an UNRELATED route in the same tenant.
//
// This is the contention case that the route-scoped key exists for: one
// tenant, two routes, one route's caller floods, the other route's caller
// must still be served. A per-tenant-only key would let one route's flood
// deny the other route.
//
// The limiter is driven directly (its own key shape is the unit under
// test), and the end-to-end path is checked too: a real request against
// the flooded route is limited while the unrelated route still answers.
import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/limits"
)

// TestAuthzRateLimitDoesNotCrossRoutes proves the limiter's key is
// route-scoped: exhausting one route's bucket leaves the other route's
// bucket untouched.
func TestAuthzRateLimitDoesNotCrossRoutes(t *testing.T) {
	th := limits.NewThrottle(5, time.Minute)

	// Flood route A's register endpoint.
	for i := 0; i < 1000; i++ {
		if th.Allow("authz:register:tenant-test:route-A") {
			continue
		}
		break
	}
	if th.Allow("authz:register:tenant-test:route-A") {
		t.Fatal("route A's bucket never filled")
	}
	// Route B, same tenant, same endpoint kind: unaffected.
	if !th.Allow("authz:register:tenant-test:route-B") {
		t.Fatal("route A's flood denied an unrelated route in the same tenant")
	}
	// A different endpoint kind on route A is also its own bucket.
	if !th.Allow("authz:token:tenant-test:route-A") {
		t.Fatal("route A's register flood denied route A's token endpoint")
	}
	// A different tenant on route A is also its own bucket.
	if !th.Allow("authz:register:tenant-other:route-A") {
		t.Fatal("route A's flood denied an unrelated tenant")
	}
}

// TestAuthzRateLimitStillBindsOneRoute proves the limiter still protects
// a single route: a flood against one route IS limited (this is the
// property the route scoping must not have broken).
func TestAuthzRateLimitStillBindsOneRoute(t *testing.T) {
	th := limits.NewThrottle(5, time.Minute)
	allowed := 0
	for i := 0; i < 1000; i++ {
		if th.Allow("authz:register:tenant-test:route-A") {
			allowed++
			continue
		}
		break
	}
	if allowed == 0 {
		t.Fatal("the limiter allowed nothing at all")
	}
	if th.Allow("authz:register:tenant-test:route-A") {
		t.Fatal("the limiter never denied a flood against one route")
	}
}

// TestManagedAuthzContentionAcrossRoutes exercises the contention
// end-to-end: a flood against one route's public OAuth endpoint returns
// 429 there, while an unrelated route in the SAME tenant keeps serving.
func TestManagedAuthzContentionAcrossRoutes(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-c1", "c1.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-c1", 1)
	routeA := publishRoute(t, s, priv, "key-test", "lse-c1", "managed-oauth")
	insertMCPLeaseRow(t, db, "lse-c2", "c2.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-c2", 1)
	routeB := publishRoute(t, s, priv, "key-test", "lse-c2", "managed-oauth")

	// Flood route A's registration endpoint.
	limited := false
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodPost,
			"https://public.example.org/r/"+routeA+"/oauth/register", nil)
		req.Host = "public.example.org"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("the flood against route A was never rate limited")
	}

	// Route B, same tenant, must still answer its metadata.
	req := httptest.NewRequest(http.MethodGet,
		"https://public.example.org/.well-known/oauth-protected-resource/r/"+routeB+"/mcp", nil)
	req.Host = "public.example.org"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("route B was denied by route A's flood: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"resource":"https://public.example.org/r/`+routeB+`/mcp"`) {
		t.Fatalf("route B's metadata is not bound to route B: %s", rec.Body.String())
	}
}
