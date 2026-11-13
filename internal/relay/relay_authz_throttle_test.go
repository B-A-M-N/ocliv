package relay

// Finding B (extras): the managed-route authz throttle must scope per
// ROUTE, not merely per tenant. Public DCR is unauthenticated, so a
// flood against one route's register endpoint must not deny a
// legitimate registration on an unrelated route in the same tenant.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ocliv/internal/lease"
	"ocliv/internal/limits"
)

func registerOn(t *testing.T, s *Server, routeID string) int {
	t.Helper()
	body := `{"client_name":"contention","redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none"}`
	req := httptest.NewRequest(http.MethodPost, "/r/"+routeID+"/oauth/register", strings.NewReader(body))
	req.Host = "public.example.org"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func TestAuthzThrottleScopesPerRoute(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "owner.t.example.test", AccessModeMCPManaged, lease.StateActive, 1, nil)
	insertMCPLeaseRow(t, db, "lse-b", "other.t.example.test", AccessModeMCPManaged, lease.StateActive, 1, nil)
	liveFabricatedSession(t, s, "lse-a", 1)
	liveFabricatedSession(t, s, "lse-b", 1)
	routeA := publishRoute(t, s, priv, "key-test", "lse-a", "managed-oauth")
	routeB := publishRoute(t, s, priv, "key-test", "lse-b", "managed-oauth")
	_ = priv

	// Flood route A well past the per-minute registration bound: the
	// shared per-tenant bucket eventually denies.
	flooded := 0
	for i := 0; i < limits.MaxBurstReg+5; i++ {
		if registerOn(t, s, routeA) == http.StatusTooManyRequests {
			flooded++
			if flooded > 2 {
				break
			}
		}
	}
	if flooded == 0 {
		t.Fatal("route A never throttled; the flood did not exercise the limiter")
	}
	// An unrelated route in the SAME tenant must still admit a
	// legitimate registration: the limiter key carries the route.
	if code := registerOn(t, s, routeB); code != http.StatusCreated {
		t.Fatalf("unrelated route contended with the flooded route: status=%d, want 201", code)
	}
}
