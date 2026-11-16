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
	"time"

	"ocliv/internal/lease"
	"ocliv/internal/limits"
)

func registerOn(t *testing.T, s *Server, routeID string) int {
	return registerOnFrom(t, s, routeID, "192.0.2.10:1234")
}

func registerOnFrom(t *testing.T, s *Server, routeID, remote string) int {
	t.Helper()
	body := `{"client_name":"contention","redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none"}`
	req := httptest.NewRequest(http.MethodPost, "/r/"+routeID+"/oauth/register", strings.NewReader(body))
	req.Host = "public.example.org"
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func TestAuthzDCRThrottleScopesPerSourceIP(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-ip", "ip.t.example.test", AccessModeMCPManaged, lease.StateActive, 1, nil)
	liveFabricatedSession(t, s, "lse-ip", 1)
	routeID := publishRoute(t, s, priv, "key-test", "lse-ip", "managed-oauth")
	s.preAuth = limits.NewThrottle(1, time.Minute)
	if code := registerOnFrom(t, s, routeID, "192.0.2.10:1234"); code != http.StatusCreated {
		t.Fatalf("first registration from ip A status=%d, want 201", code)
	}
	if code := registerOnFrom(t, s, routeID, "192.0.2.10:5678"); code != http.StatusTooManyRequests {
		t.Fatalf("second registration from ip A status=%d, want 429", code)
	}
	if code := registerOnFrom(t, s, routeID, "192.0.2.11:1234"); code != http.StatusCreated {
		t.Fatalf("registration from independent ip B contended with ip A: status=%d, want 201", code)
	}
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
