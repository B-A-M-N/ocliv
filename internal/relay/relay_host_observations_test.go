package relay

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/authz"
)

// TestRelayObservationsSeparateTransportFromJSONRPCAndEnforceRetention verifies P1:
//  1. peekMCPMethodName trusts the JSON-RPC body, never a spoofed MCP-Method header.
//  2. HTTP 200 with a JSON-RPC error on events/subscribe records TransportStatus="ok",
//     ResultCategory="error", and NEVER records StageEventsSubscriptionObserved.
//  3. server/discover without events capability does NOT record StageEventsDiscoveryObserved.
//  4. Valid events/subscribe JSON-RPC result with subscriptionId DOES record StageEventsSubscriptionObserved.
//  5. Per-route retention bounds mcp_host_observations to MaxHostObservationsPerRoute.
func TestRelayObservationsSeparateTransportFromJSONRPCAndEnforceRetention(t *testing.T) {
	// 1. Spoofed MCP-Method header must not override JSON-RPC body method.
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	req := httptest.NewRequest(http.MethodPost, "https://relay.example/r/r1/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Method", "events/subscribe")
	if got := peekMCPMethodName(req); got != "tools/list" {
		t.Fatalf("peekMCPMethodName=%q, want tools/list (must not trust spoofed MCP-Method header)", got)
	}

	// 2. Relay observation recording with real SQLite store.
	db := backupTestDB(t, t.TempDir())
	mgr, err := newAuthzManager(db)
	if err != nil {
		t.Fatalf("newAuthzManager: %v", err)
	}
	srv := &Server{
		db:      db,
		authz:   mgr,
		mcpHost: "relay.example",
		mcpPort: 443,
	}
	target := &routeTarget{TenantID: "t1", RouteID: "r1"}

	// HTTP 200 containing JSON-RPC error on events/subscribe -> MUST NOT record subscription success!
	rpcErrBody := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`)
	srv.recordManagedMCPObservation(target, "cli_1", "events/subscribe", "2026-07-28", false, http.StatusOK, "application/json", rpcErrBody)

	obs, err := mgr.Store().ListHostObservations("t1", "r1", 50)
	if err != nil {
		t.Fatalf("ListHostObservations: %v", err)
	}
	for _, o := range obs {
		if o.Stage == authz.StageEventsSubscriptionObserved {
			t.Fatalf("HTTP 200 JSON-RPC error wrongly recorded EVENTS_SUBSCRIPTION_OBSERVED: %+v", o)
		}
		if o.TransportStatus != "ok" || o.ResultCategory != "error" {
			t.Fatalf("expected transport_status=ok, result_category=error, got %+v", o)
		}
	}

	// server/discover WITHOUT events capability -> MUST NOT record EVENTS_DISCOVERY_OBSERVED.
	noEvDiscover := []byte(`{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2026-07-28","capabilities":{"tools":{}}}}`)
	srv.recordManagedMCPObservation(target, "cli_1", "server/discover", "2026-07-28", false, http.StatusOK, "application/json", noEvDiscover)
	obs, _ = mgr.Store().ListHostObservations("t1", "r1", 50)
	for _, o := range obs {
		if o.Stage == authz.StageEventsDiscoveryObserved {
			t.Fatalf("server/discover without events capability wrongly recorded EVENTS_DISCOVERY_OBSERVED: %+v", o)
		}
	}

	// Valid events/subscribe JSON-RPC result with subscriptionId -> MUST record EVENTS_SUBSCRIPTION_OBSERVED.
	okSub := []byte(`{"jsonrpc":"2.0","id":3,"result":{"subscriptionId":"sub_valid_1"}}`)
	srv.recordManagedMCPObservation(target, "cli_1", "events/subscribe", "2026-07-28", false, http.StatusOK, "application/json", okSub)
	obs, _ = mgr.Store().ListHostObservations("t1", "r1", 50)
	foundSub := false
	for _, o := range obs {
		if o.Stage == authz.StageEventsSubscriptionObserved && o.ResultCategory == "ok" && o.TransportStatus == "ok" {
			foundSub = true
		}
	}
	if !foundSub {
		t.Fatalf("valid events/subscribe result did not record EVENTS_SUBSCRIPTION_OBSERVED: %+v", obs)
	}

	// 3. Bounded per-route retention: inserting > MaxHostObservationsPerRoute keeps count capped.
	for i := 0; i < authz.MaxHostObservationsPerRoute+30; i++ {
		_ = mgr.Store().RecordHostObservation(authz.HostObservation{
			TenantID: "t1", RouteID: "r_cap", CanonicalURL: "https://relay.example/r/r_cap/mcp",
			Stage: authz.StageClientMCPObserved, TransportStatus: "ok", ResultCategory: "ok",
		})
	}
	var count int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_host_observations WHERE tenant_id='t1' AND route_id='r_cap'`).Scan(&count); err != nil {
		t.Fatalf("count observations: %v", err)
	}
	if count > authz.MaxHostObservationsPerRoute {
		t.Fatalf("host observations not bounded: count=%d, max=%d", count, authz.MaxHostObservationsPerRoute)
	}
}
