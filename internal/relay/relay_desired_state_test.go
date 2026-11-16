package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ocliv/internal/lease"
	"ocliv/internal/store"
)

func TestDesiredEnabledDisableEnableAndStalePublisher(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	otherPriv := enrollTestKey(t, db.SQL(), "key-other", "tenant-other")

	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Seed an active managed-oauth lease owned by key-test + live session.
	if _, err := db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		 VALUES('lse-1','tenant-test','key-test','my-tools.t.example.test','my-tools',8765,?,1,?,?)`,
		AccessModeMCPManaged, lease.StateActive, now,
	); err != nil {
		t.Fatal(err)
	}

	// 1. Register managed-oauth publication.
	regReq := signedMgmtRequest(t, priv, "key-test", http.MethodPost, "/v1/agent/lease/lse-1/mcp-route/managed-oauth")
	regReq.Host = "relay.example.test"
	regReq.RequestURI = "/v1/agent/lease/lse-1/mcp-route/managed-oauth"
	regW := httptest.NewRecorder()
	s.Handler().ServeHTTP(regW, regReq)
	if regW.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", regW.Code, regW.Body.String())
	}
	var reg struct {
		RouteID string `json:"route_id"`
		URL     string `json:"url"`
	}
	if err := json.Unmarshal(regW.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}

	// Seed an authz grant bound to this route to verify it survives stop/start.
	if _, err := db.SQL().Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at) VALUES('c1','tenant-test',?,'approved',?,?)`,
		reg.RouteID, now, now,
	); err != nil {
		t.Fatal(err)
	}

	// 2. Cross-owner disable must fail closed with 404.
	crossReq := signedMgmtRequest(t, otherPriv, "key-other", http.MethodPost, "/v1/agent/mcp-routes/"+reg.RouteID+"/disable")
	crossReq.Host = "relay.example.test"
	crossReq.RequestURI = "/v1/agent/mcp-routes/" + reg.RouteID + "/disable"
	crossW := httptest.NewRecorder()
	s.Handler().ServeHTTP(crossW, crossReq)
	if crossW.Code != http.StatusNotFound {
		t.Fatalf("cross-owner disable status=%d, want 404", crossW.Code)
	}

	// 3. Owner disable closes lease, evicts live session, sets desired_enabled=0.
	disReq := signedMgmtRequest(t, priv, "key-test", http.MethodPost, "/v1/agent/mcp-routes/"+reg.RouteID+"/disable")
	disReq.Host = "relay.example.test"
	disReq.RequestURI = "/v1/agent/mcp-routes/" + reg.RouteID + "/disable"
	disW := httptest.NewRecorder()
	s.Handler().ServeHTTP(disW, disReq)
	if disW.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", disW.Code, disW.Body.String())
	}
	var disOut struct {
		DesiredEnabled  bool  `json:"desired_enabled"`
		StateGeneration int64 `json:"state_generation"`
		SessionLive     bool  `json:"session_live"`
	}
	if err := json.Unmarshal(disW.Body.Bytes(), &disOut); err != nil {
		t.Fatal(err)
	}
	if disOut.DesiredEnabled || disOut.SessionLive {
		t.Fatalf("unexpected disable result: %+v", disOut)
	}

	// Public route & discovery must return non-revealing 404 when disabled.
	for _, p := range []string{
		"/r/" + reg.RouteID + "/mcp",
		"/.well-known/oauth-protected-resource/r/" + reg.RouteID + "/mcp",
		"/.well-known/oauth-authorization-server/r/" + reg.RouteID + "/oauth",
	} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = s.mcpHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("disabled %s returned %d, want 404", p, w.Code)
		}
	}

	// 4. Stale publisher with a new active lease cannot override disabled state.
	if _, err := db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		 VALUES('lse-2','tenant-test','key-test','my-tools-2.t.example.test','my-tools',8765,?,1,?,?)`,
		AccessModeMCPManaged, lease.StateActive, now,
	); err != nil {
		t.Fatal(err)
	}
	rebindReq := signedMgmtRequest(t, priv, "key-test", http.MethodPost, "/v1/agent/lease/lse-2/mcp-route/managed-oauth")
	rebindReq.Host = "relay.example.test"
	rebindReq.RequestURI = "/v1/agent/lease/lse-2/mcp-route/managed-oauth"
	rebindW := httptest.NewRecorder()
	s.Handler().ServeHTTP(rebindW, rebindReq)
	if rebindW.Code != http.StatusConflict {
		t.Fatalf("stale publisher rebind while disabled status=%d, want 409", rebindW.Code)
	}

	// 5. Re-enable, verify offline-while-enabled returns 503, then rebind at exact same URL.
	enReq := signedMgmtRequest(t, priv, "key-test", http.MethodPost, "/v1/agent/mcp-routes/"+reg.RouteID+"/enable")
	enReq.Host = "relay.example.test"
	enReq.RequestURI = "/v1/agent/mcp-routes/" + reg.RouteID + "/enable"
	enW := httptest.NewRecorder()
	s.Handler().ServeHTTP(enW, enReq)
	if enW.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", enW.Code, enW.Body.String())
	}

	reqOff := httptest.NewRequest(http.MethodGet, "/r/"+reg.RouteID+"/mcp", nil)
	reqOff.Host = s.mcpHost
	offW := httptest.NewRecorder()
	s.Handler().ServeHTTP(offW, reqOff)
	if offW.Code != http.StatusServiceUnavailable {
		t.Fatalf("offline-while-enabled status=%d, want 503", offW.Code)
	}

	rebind2Req := signedMgmtRequest(t, priv, "key-test", http.MethodPost, "/v1/agent/lease/lse-2/mcp-route/managed-oauth")
	rebind2Req.Host = "relay.example.test"
	rebind2Req.RequestURI = "/v1/agent/lease/lse-2/mcp-route/managed-oauth"
	rebind2W := httptest.NewRecorder()
	s.Handler().ServeHTTP(rebind2W, rebind2Req)
	if rebind2W.Code != http.StatusOK {
		t.Fatalf("rebind after enable status=%d body=%s", rebind2W.Code, rebind2W.Body.String())
	}
	var reg2 struct {
		RouteID string `json:"route_id"`
		URL     string `json:"url"`
	}
	if err := json.Unmarshal(rebind2W.Body.Bytes(), &reg2); err != nil {
		t.Fatal(err)
	}
	if reg2.RouteID != reg.RouteID || reg2.URL != reg.URL {
		t.Fatalf("rebind after enable changed identity: got=%+v want=%+v", reg2, reg)
	}

	// Grant is still approved!
	var grantStatus string
	if err := db.SQL().QueryRow(`SELECT status FROM authz_grants WHERE client_id='c1' AND tenant_id='tenant-test' AND route_id=?`, reg.RouteID).Scan(&grantStatus); err != nil || grantStatus != "approved" {
		t.Fatalf("grant status = %q err=%v, want approved", grantStatus, err)
	}

	// Verify schema version reached 12.
	var v int
	if err := db.SQL().QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != store.SchemaVersion {
		t.Fatalf("schema version = %d, want %d", v, store.SchemaVersion)
	}
}
