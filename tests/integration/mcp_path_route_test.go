package integration

// Single-host MCP ingress end-to-end (P0-A): a path route on the exact
// external hostname reaches a real agent-attached app, with the mount
// prefix stripped exactly once and headers preserved. The protected
// visitor policy still applies until P0-B introduces the MCP profiles.

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/limits"
)

// routeReq issues a visitor request against the harness relay with an
// explicit Host, for path-route ingress that visitorReq cannot express.
func routeReq(t *testing.T, h *harness, host, path string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.relaySrv.URL+path, strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// setLeaseMode flips a test lease into an MCP access mode after attach.
// Production leases are born with their mode (P1 `mcp publish --auth`);
// the agent protocol has no mode flag yet, so tests establish the mode
// directly. Generation and session are untouched.
func setLeaseMode(t *testing.T, h *harness, mode string) {
	t.Helper()
	if _, err := h.db.SQL().Exec(`UPDATE leases SET access_mode=? WHERE id=?`, mode, h.attached.LeaseID); err != nil {
		t.Fatal(err)
	}
}

// insertTestPublication writes a durable publication row for the
// attached lease (P1-A): ownership and label derive from the lease,
// mirroring what the production create-or-rebind path stores.
func insertTestPublication(t *testing.T, h *harness, routeID, externalHost, profile string) {
	t.Helper()
	var tenant, key, label string
	if err := h.db.SQL().QueryRow(
		`SELECT tenant_id, agent_key_id, label FROM leases WHERE id=?`,
		h.attached.LeaseID).Scan(&tenant, &key, &label); err != nil {
		t.Fatal(err)
	}
	// Verified fixture: mirrors post-activation state. Tests that
	// need the pending state create it through the real management
	// API (mgmtRouteCreate) instead, so a pending-deny can never
	// mask the defect a negative test targets.
	if _, err := h.db.SQL().Exec(
		`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, target_path, lease_id, created_at, updated_at, verified_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		routeID, tenant, key, externalHost, profile, label, "/mcp", h.attached.LeaseID,
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}

// mgmtRouteActivate activates a just-created route through the signed
// management API (P0-A): creation registers pending, activation admits.
// Tests that forward traffic through API-created routes must activate
// first; anything else asserts the pending denial.
func mgmtRouteActivate(t *testing.T, h *harness, routeID string) {
	t.Helper()
	code, raw := h.mgmt(t, h.agentKey, h.keyID, "POST", "mcp-route/"+routeID+"/activate")
	if code != http.StatusOK {
		t.Fatalf("route activate status=%d body=%q, want 200", code, raw)
	}
}

func insertTestRoute(t *testing.T, h *harness, routeID string, host ...string) {
	t.Helper()
	externalHost := "public.example.org"
	if len(host) > 0 {
		externalHost = host[0]
	}
	insertTestPublication(t, h, routeID, externalHost, "upstream-oauth")
}

// TestPathRouteForwardsStrippedPath is the P0-A vertical slice: a route
// bound to the attached lease admits a credentialed request on the exact
// external host, and the backend /mcp handler answers — proving the
// /r/<route-id> prefix was stripped exactly once before forwarding.
func TestPathRouteForwardsStrippedPath(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	setLeaseMode(t, h, "mcp_upstream_oauth")
	insertTestRoute(t, h, "route-e2e")

	before := app.postHits.Load()
	// No Ocliv credential at all: the upstream-OAuth profile neither
	// demands nor consults it. The application bearer travels for the
	// upstream resource server to validate.
	resp := routeReq(t, h, "public.example.org", "/r/route-e2e/mcp", map[string]string{
		"Content-Type":         "application/json",
		"Authorization":        "Bearer upstream-token-123",
		"MCP-Protocol-Version": "2026-07-28",
	})
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("route status=%d body=%q, want 200", resp.StatusCode, body)
	}
	if got := app.postHits.Load() - before; got != 1 {
		t.Fatalf("route forwarded %d POSTs, want exactly 1", got)
	}
	var out struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Result  struct {
			Tools []string `json:"tools"`
		} `json:"result"`
		Observed struct {
			AppAuth   string `json:"app_auth"`
			RelayAuth string `json:"relay_auth"`
			ProtoVer  string `json:"mcp_protocol_version"`
		} `json:"observed"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("backend /mcp reply unparseable: %v (%q)", err, body)
	}
	if out.JSONRPC != "2.0" || out.Result.Tools == nil {
		t.Fatalf("backend /mcp did not answer through the route: %q", body)
	}
	// P0-B header boundary through the route: the application bearer
	// arrives byte-identical for upstream validation; Ocliv's own
	// credential never reaches the child; protocol version passes
	// through for the endpoints to negotiate.
	if out.Observed.AppAuth != "Bearer upstream-token-123" {
		t.Errorf("application Authorization corrupted: %q", out.Observed.AppAuth)
	}
	if out.Observed.RelayAuth != "" {
		t.Errorf("relay credential reached app: %q", out.Observed.RelayAuth)
	}
	if out.Observed.ProtoVer != "2026-07-28" {
		t.Errorf("MCP-Protocol-Version not preserved: %q", out.Observed.ProtoVer)
	}
}

// TestPathRouteIgnoresInvalidOclivCredential: inside the upstream-OAuth
// profile there is no fallback to (and no validation of) Ocliv visitor
// credentials. A garbage Ocliv header alongside the upstream bearer
// still forwards — the relay never consults it.
// TestPathRouteDiscoveryForwardsUpstream404: protected-resource
// discovery on a path route is admitted (even pending) and rewritten
// to the server-root well-known form; an upstream without OAuth
// answers 404 and the relay forwards it unmasked. A 404 here means
// the upstream serves no discovery document — not a broken route —
// and verify must report discovery failure, never success.
func TestPathRouteDiscoveryForwardsUpstream404(t *testing.T) {
	var mu sync.Mutex
	var upstreamPaths []string
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamPaths = append(upstreamPaths, r.URL.Path)
		mu.Unlock()
		mux.ServeHTTP(w, r) // unregistered paths (incl. well-known) 404
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() { _ = srv.Serve(ln) }()
	appPort := ln.Addr().(*net.TCPAddr).Port

	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, appPort)
	setLeaseMode(t, h, "mcp_upstream_oauth")
	insertTestRoute(t, h, "route-disc404")

	req, err := http.NewRequest(http.MethodGet,
		h.relaySrv.URL+"/.well-known/oauth-protected-resource/r/route-disc404/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "public.example.org"
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("discovery status=%d, want upstream 404 forwarded unmasked", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, p := range upstreamPaths {
		if p == "/.well-known/oauth-protected-resource/mcp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("upstream never saw the rewritten discovery path: %v", upstreamPaths)
	}
}

func TestPathRouteIgnoresInvalidOclivCredential(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	setLeaseMode(t, h, "mcp_upstream_oauth")
	insertTestRoute(t, h, "route-garbage")

	resp := routeReq(t, h, "public.example.org", "/r/route-garbage/mcp", map[string]string{
		"Content-Type":          "application/json",
		"X-Ocliv-Authorization": "Bearer garbage-not-a-token",
		"Authorization":         "Bearer upstream-token-123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("garbage Ocliv credential blocked OAuth route: got %d, want 200", resp.StatusCode)
	}
}

// TestPathRouteModeMismatchDenied: an OAuth route to a lease left in the
// default protected mode is an unsupported combination — denied before
// any forwarding, even with a valid Ocliv credential.
func TestPathRouteModeMismatchDenied(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	// Lease stays "protected": no setLeaseMode call.
	insertTestRoute(t, h, "route-mismatch")

	raw := shareRaw(t, h)
	before := app.postHits.Load()
	resp := routeReq(t, h, "public.example.org", "/r/route-mismatch/mcp", map[string]string{
		"Content-Type":          "application/json",
		"X-Ocliv-Authorization": "Bearer " + raw,
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("mismatched route: got %d, want 404", resp.StatusCode)
	}
	if got := app.postHits.Load() - before; got != 0 {
		t.Fatalf("mismatched route reached upstream %d times, want 0", got)
	}
}

// TestPathRouteRevokedLeaseDenied: revoking the bound lease denies the
// route (503) with no further forwarding.
func TestPathRouteRevokedLeaseDenied(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	setLeaseMode(t, h, "mcp_upstream_oauth")
	insertTestRoute(t, h, "route-revoked")

	if _, err := h.db.SQL().Exec(`UPDATE leases SET status='REVOKED' WHERE id=?`, h.attached.LeaseID); err != nil {
		t.Fatal(err)
	}
	before := app.postHits.Load()
	resp := routeReq(t, h, "public.example.org", "/r/route-revoked/mcp", map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer upstream-token-123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("revoked route: got %d, want 503", resp.StatusCode)
	}
	if got := app.postHits.Load() - before; got != 0 {
		t.Fatalf("revoked route reached upstream %d times, want 0", got)
	}
}

// TestPathRouteDeeperPathRejected proves stripping happens exactly once:
// /r/<id>/mcp/extra is not a route and is never forwarded (404, zero
// upstream contact), even with a valid credential.
func TestPathRouteDeeperPathRejected(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	insertTestRoute(t, h, "route-deep")

	raw := shareRaw(t, h)
	before := app.postHits.Load()
	resp := routeReq(t, h, "public.example.org", "/r/route-deep/mcp/extra", map[string]string{
		"X-Ocliv-Authorization": "Bearer " + raw,
		"Content-Type":          "application/json",
	})
	resp.Body.Close()
	// Not a route path, so existing wildcard handling applies: the
	// external host is no tunnel hostname, failing closed with 400.
	// What matters is denial without forwarding, never the exact 4xx.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("deeper route path: got %d, want 400", resp.StatusCode)
	}
	if got := app.postHits.Load() - before; got != 0 {
		t.Fatalf("rejected path reached upstream %d times, want 0", got)
	}
}

// routeLive polls the signed status endpoint until the lease has a live
// session at the current generation, proving publish-time eviction does
// not brick the tunnel (the agent resumes and the route stays bound).
func routeLive(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for {
		code, raw := h.mgmt(t, h.agentKey, h.keyID, "GET", "status")
		if code == http.StatusOK {
			var st struct {
				RouteLive bool `json:"route_live"`
			}
			if err := json.Unmarshal(raw, &st); err == nil && st.RouteLive {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("route never went live after publish (status=%d body=%q)", code, raw)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func mgmtRouteCreate(t *testing.T, h *harness, profile string) (code int, routeID, url, auth string) {
	t.Helper()
	code, raw := h.mgmt(t, h.agentKey, h.keyID, "POST", "mcp-route/"+profile)
	if code != http.StatusOK {
		return code, "", "", ""
	}
	var out struct {
		RouteID string `json:"route_id"`
		URL     string `json:"url"`
		Auth    string `json:"auth"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("route create reply unparseable: %v (%q)", err, raw)
	}
	return code, out.RouteID, out.URL, out.Auth
}

// TestMCPRouteMgmtLifecycle is the P1 publish vertical slice at the
// relay API: create flips a protected lease into the OAuth mode,
// republishing is idempotent (stable endpoint), listing reports the
// route, the tunnel recovers after publish-time eviction, and deletion
// removes the route while the lease survives.
func TestMCPRouteMgmtLifecycle(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	// The tunnel is born in the OAuth mode (P1 serve --auth): the route
	// binds to the requested policy, never flips it in place.
	h.startAgentOpts(t, app.Port, config.Agent{AccessMode: "mcp_upstream_oauth"})

	code, rid, url, auth := mgmtRouteCreate(t, h, "upstream-oauth")
	if code != http.StatusOK {
		t.Fatalf("route create status=%d", code)
	}
	if rid == "" || auth != "upstream-oauth" {
		t.Fatalf("route create reply incomplete: id=%q auth=%q", rid, auth)
	}
	wantPrefix := "https://public.example.org/r/" + rid + "/mcp"
	if url != wantPrefix {
		t.Fatalf("route url=%q want %q", url, wantPrefix)
	}
	var mode string
	if err := h.db.SQL().QueryRow(`SELECT access_mode FROM leases WHERE id=?`, h.attached.LeaseID).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "mcp_upstream_oauth" {
		t.Fatalf("lease not born in the requested mode: %q", mode)
	}

	// Stable endpoint: republishing returns the same route ID.
	_, rid2, _, _ := mgmtRouteCreate(t, h, "upstream-oauth")
	if rid2 != rid {
		t.Fatalf("republish minted %q, want stable %q", rid2, rid)
	}

	// Creation registers pending: activation admits (P0-A).
	mgmtRouteActivate(t, h, rid)

	// Listing reports the route (mcp doctor's source).
	code, raw := h.mgmt(t, h.agentKey, h.keyID, "GET", "mcp-route")
	if code != http.StatusOK || !strings.Contains(string(raw), rid) {
		t.Fatalf("route list status=%d body=%q", code, raw)
	}

	// The route admits the live generation with no eviction involved:
	// creation changes no lease state, so the tunnel never drops.
	routeLive(t, h)
	before := app.postHits.Load()
	resp := routeReq(t, h, "public.example.org", "/r/"+rid+"/mcp", map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer upstream-token-123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-publish route status=%d, want 200", resp.StatusCode)
	}
	if got := app.postHits.Load() - before; got != 1 {
		t.Fatalf("post-publish route forwarded %d POSTs, want 1", got)
	}

	// Deletion removes the route; the lease itself survives.
	code, _ = h.mgmt(t, h.agentKey, h.keyID, "DELETE", "mcp-route/"+rid)
	if code != http.StatusOK {
		t.Fatalf("route delete status=%d, want 200", code)
	}
	code, raw = h.mgmt(t, h.agentKey, h.keyID, "GET", "mcp-route")
	if code != http.StatusOK || strings.Contains(string(raw), rid) {
		t.Fatalf("route still listed after delete: status=%d body=%q", code, raw)
	}
	before = app.postHits.Load()
	resp = routeReq(t, h, "public.example.org", "/r/"+rid+"/mcp", map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer upstream-token-123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted route: got %d, want 404", resp.StatusCode)
	}
	if got := app.postHits.Load() - before; got != 0 {
		t.Fatalf("deleted route reached upstream %d times", got)
	}
}

// TestMCPRouteConcurrentCreate (P1-4): N simultaneous publications with
// distinct management nonces must converge on one stable route identifier
// with exactly one mapping row — no duplicate routes for the same
// (lease, host, profile) publication.
func TestMCPRouteConcurrentCreate(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{AccessMode: "mcp_upstream_oauth"})

	const n = 16
	var start sync.WaitGroup
	start.Add(1)
	ids := make([]string, n)
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			codes[i], ids[i], _, _ = mgmtRouteCreate(t, h, "upstream-oauth")
		}(i)
	}
	start.Done()
	wg.Wait()
	for i := 0; i < n; i++ {
		if codes[i] != http.StatusOK {
			t.Fatalf("create %d status=%d, want 200", i, codes[i])
		}
		if ids[i] == "" || ids[i] != ids[0] {
			t.Fatalf("create %d route_id=%q, want stable %q", i, ids[i], ids[0])
		}
	}
	var count int
	if err := h.db.SQL().QueryRow(
		`SELECT COUNT(*) FROM mcp_publications WHERE lease_id=? AND external_host=? AND profile=?`,
		h.attached.LeaseID, "public.example.org", "upstream-oauth").Scan(&count); err != nil || count != 1 {
		t.Fatalf("mapping rows=%d err=%v, want exactly 1", count, err)
	}
}

// TestMCPRouteMgmtDenials pins the failure contract: unknown profiles,
// unconfigured ingress, inactive leases, unknown routes, and foreign
// keys are all refused without state changes.
func TestMCPRouteMgmtDenials(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)

	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "POST", "mcp-route/superuser"); code != http.StatusBadRequest {
		t.Errorf("bogus profile: got %d, want 400", code)
	}
	if code, _ := h.mgmt(t, h.agentKey, h.keyID, "DELETE", "mcp-route/does-not-exist"); code != http.StatusNotFound {
		t.Errorf("unknown route delete: got %d, want 404", code)
	}
	other, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := h.mgmt(t, other, "key-"+string(other.ID()), "POST", "mcp-route/upstream-oauth"); code != http.StatusForbidden {
		t.Errorf("foreign key route create: got %d, want 403", code)
	}

	// Relay without route ingress configured: honest 409, no row.
	h2 := newHarness(t)
	defer h2.db.Close()
	defer h2.relaySrv.Close()
	h2.startAgent(t, app.Port)
	if code, _ := h2.mgmt(t, h2.agentKey, h2.keyID, "POST", "mcp-route/upstream-oauth"); code != http.StatusConflict {
		t.Errorf("unconfigured ingress create: got %d, want 409", code)
	}

	// Inactive lease: revoke first, then create is refused.
	h3 := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h3.db.Close()
	defer h3.relaySrv.Close()
	h3.startAgent(t, app.Port)
	if code, _ := h3.mgmt(t, h3.agentKey, h3.keyID, "POST", "revoke"); code != http.StatusOK {
		t.Fatalf("revoke status=%d", code)
	}
	if code, _ := h3.mgmt(t, h3.agentKey, h3.keyID, "POST", "mcp-route/upstream-oauth"); code != http.StatusConflict {
		t.Errorf("revoked-lease create: got %d, want 409", code)
	}
}

// TestMCPModeLeaseResumeSurvivesRestart: an MCP-mode lease resumes
// across agent restarts — the strict mode equality admits the owner's
// own mode, so the route stays bound to the same lease ID without
// republishing.
func TestMCPModeLeaseResumeSurvivesRestart(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{AccessMode: "mcp_upstream_oauth"})
	firstID := h.attached.LeaseID

	code, rid, _, _ := mgmtRouteCreate(t, h, "upstream-oauth")
	if code != http.StatusOK {
		t.Fatalf("route create status=%d", code)
	}
	mgmtRouteActivate(t, h, rid)
	h.restartAgent(t, app.Port)
	if h.attached.LeaseID != firstID {
		t.Fatalf("restart minted %q, want resumed %q", h.attached.LeaseID, firstID)
	}
	routeLive(t, h)
	before := app.postHits.Load()
	// Resolve the stable route ID from the listing (no republish).
	code, raw := h.mgmt(t, h.agentKey, h.keyID, "GET", "mcp-route")
	if code != http.StatusOK {
		t.Fatalf("route list status=%d", code)
	}
	var list struct {
		Routes []struct {
			RouteID string `json:"route_id"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &list); err != nil || len(list.Routes) != 1 {
		t.Fatalf("route list after restart: %q", raw)
	}
	resp := routeReq(t, h, "public.example.org", "/r/"+list.Routes[0].RouteID+"/mcp", map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer upstream-token-123",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-restart route status=%d, want 200", resp.StatusCode)
	}
	if got := app.postHits.Load() - before; got != 1 {
		t.Fatalf("post-restart route forwarded %d POSTs, want 1", got)
	}
}

// TestMCPWildcardPathRestricted: in a wildcard deployment, an MCP-mode
// lease must expose exactly /mcp — every other path is denied before any
// yamux stream opens (P0-3), with zero upstream contact. Variants cover
// trailing slashes, case, subpaths, and percent-encoded bypasses.
func TestMCPWildcardPathRestricted(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	setLeaseMode(t, h, "mcp_upstream_oauth")

	before := app.postHits.Load()
	denied := []string{"/admin", "/mcp/", "/MCP", "/mcp/extra", "/other.json", "/%6dcp"}
	for _, p := range denied {
		resp := routeReq(t, h, h.host(), p, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer [REDACTED]",
		})
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("wildcard MCP path %q: got %d body %q, want 404", p, resp.StatusCode, body)
		}
		if got := app.postHits.Load() - before; got != 0 {
			t.Fatalf("wildcard MCP path %q forwarded %d POSTs, want zero upstream contact", p, got)
		}
	}
	// The one published endpoint still works through the same lease.
	resp := routeReq(t, h, h.host(), "/mcp", map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer [REDACTED]",
	})
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wildcard /mcp: got %d body %q, want 200", resp.StatusCode, body)
	}
	if got := app.postHits.Load() - before; got != 1 {
		t.Fatalf("wildcard /mcp forwarded %d POSTs, want exactly 1", got)
	}
}

// TestSameHostRouteEndToEnd is the single-host deployment shape
// (Caddyfile.single-host, temporary *.ts.net ingress): the external MCP
// hostname IS the relay control hostname. A route bound to the attached
// lease admits a request on the shared host and the backend answers,
// proving the authority passthrough from the unit test carries a full
// exchange — not just a 404-vs-421 distinction.
func TestSameHostRouteEndToEnd(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "relay.example.test")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	setLeaseMode(t, h, "mcp_upstream_oauth")
	insertTestRoute(t, h, "route-samehost", "relay.example.test")

	before := app.postHits.Load()
	resp := routeReq(t, h, "relay.example.test", "/r/route-samehost/mcp", map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer [REDACTED]",
	})
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-host route status=%d body=%q, want 200", resp.StatusCode, body)
	}
	if got := app.postHits.Load() - before; got != 1 {
		t.Fatalf("same-host route forwarded %d POSTs, want exactly 1", got)
	}
}

// TestMCPAdmissionRateBoundsFlood (P1-10): MCP profiles bypass Ocliv
// visitor authentication, so an unauthenticated flood must meet a
// dedicated pre-forwarding rate budget. Hammering a fixture route far
// past the per-source budget must yield 429s, and every non-rejected
// request must reach upstream exactly once — no silent drops, no
// monopolized slots.
func TestMCPAdmissionRateBoundsFlood(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	setLeaseMode(t, h, "mcp_anonymous_fixture")

	insertTestPublication(t, h, "route-flood", "public.example.org", "fixture-anonymous")
	const total = 300
	var ok, rejected int
	before := app.postHits.Load()
	for i := 0; i < total; i++ {
		resp := routeReq(t, h, "public.example.org", "/r/route-flood/mcp", map[string]string{
			"Content-Type": "application/json",
		})
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			rejected++
		default:
			t.Fatalf("request %d: status=%d, want 200 or 429", i, resp.StatusCode)
		}
	}
	if rejected == 0 {
		t.Fatalf("unauthenticated flood of %d never rate-limited", total)
	}
	if ok != limits.MCPAdmissionBurst || rejected != total-limits.MCPAdmissionBurst {
		t.Fatalf("admission budget off: ok=%d rejected=%d, want %d/%d", ok, rejected, limits.MCPAdmissionBurst, total-limits.MCPAdmissionBurst)
	}
	if got := app.postHits.Load() - before; got != int64(ok) {
		t.Fatalf("upstream saw %d executions for %d admitted requests", got, ok)
	}
}

// TestPathRouteAnonymousFixture: the fixture-anonymous profile serves
// without any credential, for an explicitly safe demonstration tool
// only. The fixture /mcp endpoint stands in for that read-only demo.
func TestPathRouteAnonymousFixture(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarnessNS(t, "t.example.test", "relay.example.test", "public.example.org")
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgent(t, app.Port)
	setLeaseMode(t, h, "mcp_anonymous_fixture")

	insertTestPublication(t, h, "route-fixture", "public.example.org", "fixture-anonymous")
	before := app.postHits.Load()
	resp := routeReq(t, h, "public.example.org", "/r/route-fixture/mcp", map[string]string{
		"Content-Type": "application/json",
	})
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fixture route: got %d body=%q, want 200", resp.StatusCode, body)
	}
	if got := app.postHits.Load() - before; got != 1 {
		t.Fatalf("fixture route forwarded %d POSTs, want exactly 1", got)
	}
}
