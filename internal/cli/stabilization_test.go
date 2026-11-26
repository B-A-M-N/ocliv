package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestStabilizationImmutableServiceIDGrantFailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	pol := AgentPermissionsPolicy{
		SchemaVersion: 2,
		Agents: map[string]AgentPermissionRule{
			"agent-1": {
				Grants: []ServiceGrant{
					{
						ServiceID:   "svc-immutable-1",
						ServiceName: "demo",
						Actions:     []string{"inspect", "lifecycle"},
					},
					{
						ServiceName:      "newapp",
						Actions:          []string{"deployment"},
						AllowedPorts:     []int{9090},
						AllowedAuthModes: []string{"ocliv-managed"},
					},
				},
			},
		},
	}

	// ID-bound grant must require exact immutable service ID.
	if ok, _, _ := pol.check("agent-1", "inspect", "demo", "svc-immutable-1", 0, ""); !ok {
		t.Fatal("expected exact immutable service_id match to succeed")
	}
	if ok, _, _ := pol.check("agent-1", "inspect", "demo", "", 0, ""); ok {
		t.Fatal("ID-bound grant must fail closed when service_id is absent")
	}
	if ok, _, _ := pol.check("agent-1", "inspect", "demo", "svc-recreated-2", 0, ""); ok {
		t.Fatal("ID-bound grant must fail closed when service_id mismatches (recreated service)")
	}
	if pol.canAccessService("agent-1", "demo", "") {
		t.Fatal("canAccessService must fail closed for ID-bound grant with empty service_id")
	}

	// Name-only creation grant works before deployment assigns an immutable ID,
	// then promotes cleanly to the resulting immutable ID via bindNameOnlyGrantsToServiceID.
	if ok, _, _ := pol.check("agent-1", "deployment", "newapp", "", 9090, "ocliv-managed"); !ok {
		t.Fatal("expected name-only creation grant to allow initial deployment")
	}
	if err := saveAgentPermissionsPolicy(pol); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	if err := bindNameOnlyGrantsToServiceID("agent-1", "newapp", "svc-newapp-99"); err != nil {
		t.Fatalf("bindNameOnlyGrantsToServiceID: %v", err)
	}
	reloaded, err := loadAgentPermissionsPolicy()
	if err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	if ok, _, _ := reloaded.check("agent-1", "deployment", "newapp", "", 9090, "ocliv-managed"); ok {
		t.Fatal("promoted grant must now fail closed when service_id is absent")
	}
	if ok, _, _ := reloaded.check("agent-1", "deployment", "newapp", "svc-newapp-99", 9090, "ocliv-managed"); !ok {
		t.Fatal("promoted grant must match the bound immutable service_id")
	}
}

func TestStabilizationApprovalBindsResolvedPublicationAndRejectsStaleIntent(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://relay.example.test")
	tmpDir := t.TempDir()
	t.Setenv("OCLIV_PERMISSIONS_FILE", filepath.Join(tmpDir, "agent-permissions.json"))
	t.Setenv("OCLIV_APPROVAL_REQUESTS_FILE", filepath.Join(tmpDir, "approval-requests.json"))

	k, keyID, err := loadKeyForProfile(config.ActiveProfile())
	if err != nil {
		t.Fatalf("loadKeyForProfile: %v", err)
	}
	store, err := openServices()
	if err != nil {
		t.Fatalf("openServices: %v", err)
	}
	if err := store.Put(config.ServiceRecord{
		Name:          "demo",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		Profile:       config.ActiveProfile(),
		RelayURL:      "https://relay.example.test",
		PublicationID: "pub-stale-local",
		DesiredState:  config.DesiredEnabled,
		Identity:      &config.HostedServiceIdentity{ServiceID: "svc-demo-1", PublicationID: "pub-stale-local"},
	}); err != nil {
		t.Fatalf("put service: %v", err)
	}

	// Start with read-only permissions so revoke_client requires single-use approval.
	if err := saveAgentPermissionsPolicy(AgentPermissionsPolicy{
		SchemaVersion: 2,
		Agents: map[string]AgentPermissionRule{
			"local-stdio": {
				Grants: []ServiceGrant{{ServiceID: "svc-demo-1", ServiceName: "demo", Actions: []string{"inspect"}}},
			},
		},
	}); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	resolveCalls := 0
	revokeCalled := false
	currentPub := "pub-authoritative-1"
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				resolveCalls++
				// On the 3rd call (post-approval revalidation), simulate publication changing!
				pub := currentPub
				if resolveCalls >= 3 {
					pub = "pub-authoritative-2"
				}
				return http.StatusOK, []byte(`{"publications":[{"route_id":"` + pub + `","pub_name":"demo","url":"https://relay.example.test/r/` + pub + `/mcp","publication_state":"ACTIVE","session_live":true,"admission":"READY"}]}`), nil
			}
			if method == http.MethodPost && strings.Contains(path, "/authz/revoke/") {
				revokeCalled = true
				return http.StatusOK, []byte(`{"ok":true}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
	}

	// 1. First call requests approval; intent must bind the RESOLVED publication ID (pub-authoritative-1), not pub-stale-local.
	raw1, err := handleMCPManageTool("local-stdio", "revoke_client", map[string]any{"service": "demo", "clientId": "cli_test123"}, "https://relay.example.test", k, keyID, ops)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	res1 := raw1.(map[string]any)
	if res1["status"] != "OPERATOR_AUTHORIZATION_REQUIRED" {
		t.Fatalf("expected OPERATOR_AUTHORIZATION_REQUIRED, got %#v", res1)
	}
	reqs, _ := listOperatorApprovalRequests()
	if len(reqs) != 1 || reqs[0].PublicationID != "pub-authoritative-1" {
		t.Fatalf("expected approval request bound to resolved pub-authoritative-1, got %#v", reqs)
	}

	// 2. Operator approves once.
	if _, err := decideOperatorApprovalRequest(reqs[0].RequestID, "allow_once"); err != nil {
		t.Fatalf("approve once: %v", err)
	}

	// 3. Second call resolves pub-authoritative-1 (matches approval), then revalidates
	// and sees pub-authoritative-2 -> must return INTENT_STALE without calling relay revoke!
	raw2, err := handleMCPManageTool("local-stdio", "revoke_client", map[string]any{"service": "demo", "clientId": "cli_test123"}, "https://relay.example.test", k, keyID, ops)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	res2 := raw2.(map[string]any)
	if res2["status"] != "INTENT_STALE" {
		t.Fatalf("expected INTENT_STALE when publication changed after approval, got %#v", res2)
	}
	if revokeCalled {
		t.Fatal("relay revoke must NOT execute when publication changed after approval")
	}
}

func TestStabilizationControlCenterCASGoogleIdempotencyAndAuditFailClosed(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://relay.example.test")
	k, keyID, err := loadKeyForProfile(config.ActiveProfile())
	if err != nil {
		t.Fatalf("loadKeyForProfile: %v", err)
	}
	tmpDir := t.TempDir()
	t.Setenv("OCLIV_PERMISSIONS_FILE", filepath.Join(tmpDir, "agent-permissions.json"))
	t.Setenv("OCLIV_APPROVAL_REQUESTS_FILE", filepath.Join(tmpDir, "approval-requests.json"))

	store, err := openServices()
	if err != nil {
		t.Fatalf("openServices: %v", err)
	}
	if err := store.Put(config.ServiceRecord{
		Name:          "demo",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		Profile:       config.ActiveProfile(),
		RelayURL:      "https://relay.example.test",
		PublicationID: "pub-demo",
		PublicURL:     "https://relay.example.test/r/pub-demo/mcp",
		DesiredState:  config.DesiredEnabled,
		Identity:      &config.HostedServiceIdentity{ServiceID: "svc-demo-1", PublicationID: "pub-demo"},
	}); err != nil {
		t.Fatalf("put service: %v", err)
	}

	registerCount := 0
	var lastRefreshPolicy string
	revokedClients := []string{}
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, []byte(`{"publications":[{"route_id":"pub-demo","pub_name":"demo","url":"https://relay.example.test/r/pub-demo/mcp","publication_state":"ACTIVE","session_live":true,"admission":"READY"}]}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
		mgmtCallBody: func(_ string, _ *identity.KeyPair, _, method, path string, body []byte) (int, []byte, error) {
			if method == http.MethodPost && path == "/v1/agent/mcp-routes/pub-demo/authz/register" {
				registerCount++
				var p map[string]any
				_ = json.Unmarshal(body, &p)
				lastRefreshPolicy, _ = p["refresh_policy"].(string)
				cid := "cli_google_1"
				if registerCount > 1 {
					cid = "cli_google_2"
				}
				return http.StatusCreated, []byte(`{"client_id":"` + cid + `","client_secret":"sec_` + cid + `","status":"approved"}`), nil
			}
			if method == http.MethodPost && strings.HasPrefix(path, "/v1/agent/mcp-routes/pub-demo/authz/revoke/") {
				revokedClients = append(revokedClients, strings.TrimPrefix(path, "/v1/agent/mcp-routes/pub-demo/authz/revoke/"))
				return http.StatusOK, []byte(`{"ok":true}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
	}

	cc, err := newControlCenterServer("127.0.0.1:43211", "https://relay.example.test", k, keyID, ops)
	if err != nil {
		t.Fatalf("newControlCenterServer: %v", err)
	}

	// Establish operator session via single-use bootstrap token.
	reqBoot := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:43211/auth?token="+cc.bootstrapToken, nil)
	reqBoot.Host = "127.0.0.1:43211"
	recBoot := httptest.NewRecorder()
	cc.ServeHTTP(recBoot, reqBoot)
	if recBoot.Code != http.StatusSeeOther {
		t.Fatalf("bootstrap failed: %d", recBoot.Code)
	}
	cookie := recBoot.Result().Cookies()[0]

	doReq := func(method, path string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		var buf bytes.Buffer
		if payload != nil {
			_ = json.NewEncoder(&buf).Encode(payload)
		}
		req := httptest.NewRequest(method, "http://127.0.0.1:43211"+path, &buf)
		req.Host = "127.0.0.1:43211"
		req.Header.Set("Origin", "http://127.0.0.1:43211")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Ocliv-CSRF", cc.csrfToken)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		cc.ServeHTTP(rec, req)
		return rec
	}

	// 1. PUT /api/agents/permissions without expected_revision must fail with 400.
	resp := doReq(http.MethodPut, "/api/agents/permissions", map[string]any{"policy": defaultLocalAgentPermissionsPolicy()})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when expected_revision omitted, got %d (%s)", resp.Code, resp.Body.String())
	}

	// 2. Repeated POST /api/services/demo/connect-google must be idempotent and use google_confidential.
	r1 := doReq(http.MethodPost, "/api/services/demo/connect-google", map[string]any{
		"type":         "gemini",
		"redirect_uri": "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp",
	})
	var g1 map[string]any
	_ = json.NewDecoder(r1.Body).Decode(&g1)
	if r1.Code != http.StatusOK || g1["client_id"] != "cli_google_1" || g1["idempotent"] != false {
		t.Fatalf("first connect-google failed: status=%d body=%#v", r1.Code, g1)
	}
	if lastRefreshPolicy != "google_confidential" {
		t.Fatalf("expected refresh_policy=google_confidential, got %q", lastRefreshPolicy)
	}

	// Second click with identical params must NOT register a duplicate client!
	r2 := doReq(http.MethodPost, "/api/services/demo/connect-google", map[string]any{
		"type":         "gemini",
		"redirect_uri": "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp",
	})
	var g2 map[string]any
	_ = json.NewDecoder(r2.Body).Decode(&g2)
	if r2.Code != http.StatusOK || g2["idempotent"] != true || g2["client_id"] != "cli_google_1" {
		t.Fatalf("second connect-google must be idempotent: status=%d body=%#v", r2.Code, g2)
	}
	if registerCount != 1 {
		t.Fatalf("expected exactly 1 relay registration on repeated clicks, got %d", registerCount)
	}

	// 3. Rotate (update=true) creates cli_google_2 and revokes cli_google_1.
	r3 := doReq(http.MethodPost, "/api/services/demo/connect-google", map[string]any{
		"type":         "gemini",
		"redirect_uri": "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp",
		"update":       true,
	})
	var g3 map[string]any
	_ = json.NewDecoder(r3.Body).Decode(&g3)
	if r3.Code != http.StatusOK || g3["client_id"] != "cli_google_2" {
		t.Fatalf("rotate connect-google failed: status=%d body=%#v", r3.Code, g3)
	}
	if len(revokedClients) != 1 || revokedClients[0] != "cli_google_1" {
		t.Fatalf("expected old client cli_google_1 revoked during rotation, got %v", revokedClients)
	}

	// 4. DELETE revokes active client and subsequent POST without reconnect=true fails with 409.
	r4 := doReq(http.MethodDelete, "/api/services/demo/connect-google", nil)
	if r4.Code != http.StatusOK {
		t.Fatalf("DELETE connect-google failed: %d (%s)", r4.Code, r4.Body.String())
	}
	r5 := doReq(http.MethodPost, "/api/services/demo/connect-google", map[string]any{
		"type":         "gemini",
		"redirect_uri": "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp",
	})
	if r5.Code != http.StatusConflict {
		t.Fatalf("expected 409 refusing to resurrect revoked binding without reconnect=true, got %d (%s)", r5.Code, r5.Body.String())
	}
}

func TestStabilizationAuthenticatedDiagnosticVerificationSeparatesExternalAcceptance(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://relay.example.test")
	k, keyID, err := loadKeyForProfile(config.ActiveProfile())
	if err != nil {
		t.Fatalf("loadKeyForProfile: %v", err)
	}

	// Mint a real short-lived diagnostic token with authz.Issuer and verify it against
	// an isolated mock public MCP endpoint that enforces Bearer auth & advertises Events.
	issuer, err := authz.NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	var pubSrv *httptest.Server
	pubSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/r/pub-diag/mcp":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resource":              pubSrv.URL + "/r/pub-diag/mcp",
				"authorization_servers": []string{pubSrv.URL + "/r/pub-diag"},
			})
		case "/.well-known/oauth-authorization-server/r/pub-diag":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                           pubSrv.URL + "/r/pub-diag",
				"authorization_endpoint":           pubSrv.URL + "/r/pub-diag/oauth/authorize",
				"token_endpoint":                   pubSrv.URL + "/r/pub-diag/oauth/token",
				"jwks_uri":                         pubSrv.URL + "/r/pub-diag/oauth/jwks.json",
				"response_types_supported":         []string{"code"},
				"grant_types_supported":            []string{"authorization_code"},
				"code_challenge_methods_supported": []string{"S256"},
			})
		case "/r/pub-diag/mcp":
			authHdr := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHdr, "Bearer ") {
				w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+pubSrv.URL+`/.well-known/oauth-protected-resource/r/pub-diag/mcp"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			claims, verr := issuer.Verify(strings.TrimPrefix(authHdr, "Bearer "))
			if verr != nil || claims.TokenType != "diagnostic" || claims.Subject != authz.DiagnosticProbeSubject {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var rpc struct {
				ID     any    `json:"id"`
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&rpc)
			w.Header().Set("Content-Type", "application/json")
			switch rpc.Method {
			case "initialize":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": rpc.ID,
					"result": map[string]any{
						"protocolVersion": "2025-03-26",
						"capabilities":    map[string]any{"tools": map[string]any{}, "events": map[string]any{}},
						"serverInfo":      map[string]any{"name": "diag-fixture", "version": "1.0"},
					},
				})
			case "server/discover":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": rpc.ID,
					"result": map[string]any{
						"capabilities": map[string]any{"tools": map[string]any{}, "events": map[string]any{}},
					},
				})
			case "tools/list":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": rpc.ID,
					"result": map[string]any{"tools": []any{map[string]any{"name": "ping"}}},
				})
			case "events/list":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": rpc.ID,
					"result": map[string]any{"events": []any{map[string]any{"name": "demo.tick"}}},
				})
			default:
				w.WriteHeader(http.StatusAccepted)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer pubSrv.Close()

	pubURL := pubSrv.URL + "/r/pub-diag/mcp"
	diagTok, err := issuer.Mint(authz.TokenClaims{
		Issuer:    pubSrv.URL + "/r/pub-diag",
		Subject:   authz.DiagnosticProbeSubject,
		Audience:  pubURL,
		Tenant:    "default",
		Route:     "pub-diag",
		Scope:     "mcp:tools",
		ID:        "diag_test_1",
		Expiry:    time.Now().Add(60 * time.Second).Unix(),
		TokenType: "diagnostic",
	})
	if err != nil {
		t.Fatalf("mint diagnostic token: %v", err)
	}

	// Verify Authorizer accepts short-lived diagnostic token without a visitor client/grant.
	authzCheck := authz.NewAuthorizer(issuer, authz.NewMemStore())
	req, _ := http.NewRequest(http.MethodPost, pubURL, nil)
	req.Header.Set("Authorization", "Bearer "+diagTok)
	if claims, err := authzCheck.AuthorizeClaims(req, pubURL, pubSrv.URL+"/r/pub-diag", "default", "pub-diag"); err != nil || claims.Subject != authz.DiagnosticProbeSubject {
		t.Fatalf("Authorizer rejected valid diagnostic token: err=%v claims=%#v", err, claims)
	}

	rec := config.ServiceRecord{
		Name:          "diag",
		Type:          "mcp",
		Auth:          "ocliv-managed",
		Profile:       "default",
		RelayURL:      pubSrv.URL,
		PublicationID: "pub-diag",
		PublicURL:     pubURL,
	}
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, []byte(`{"publications":[{"route_id":"pub-diag","pub_name":"diag","url":"` + pubURL + `","publication_state":"ACTIVE","session_live":true,"admission":"READY"}]}`), nil
			}
			if method == http.MethodPost && path == "/v1/agent/mcp-routes/pub-diag/authz/diagnostic-token" {
				return http.StatusOK, []byte(`{"route_id":"pub-diag","access_token":"` + diagTok + `","token_type":"Bearer","synthetic":true}`), nil
			}
			return http.StatusNotFound, nil, nil
		},
	}

	// Run runAuthenticatedServiceVerification with pubSrv's TLS client.
	u, _ := url.Parse(pubURL)
	_ = u
	v := runAuthenticatedServiceVerification(rec, pubSrv.URL, k, keyID, ops, pubSrv.Client(), false)
	if !v.OK {
		t.Fatalf("expected authenticated verification OK, got %#v", v)
	}
	if v.VerificationSource != "synthetic_diagnostic_probe" {
		t.Fatalf("expected synthetic_diagnostic_probe, got %q", v.VerificationSource)
	}
	if v.Stages["authenticated_mcp_handshake"] != "PASS" {
		t.Fatalf("expected authenticated_mcp_handshake=PASS, got %#v", v.Stages)
	}
	if v.Stages["events_advertised"] != "PASS" || v.Stages["events_list_verified"] != "PASS" {
		t.Fatalf("expected events stages PASS, got %#v", v.Stages)
	}
	// Synthetic diagnostic probe MUST NOT claim external client acceptance!
	if v.Stages["external_client_acceptance"] != "UNVERIFIED" {
		t.Fatalf("synthetic probe must keep external_client_acceptance=UNVERIFIED, got %q", v.Stages["external_client_acceptance"])
	}
	// Ensure token is never leaked into Detail.
	if strings.Contains(v.Detail, diagTok) {
		t.Fatal("diagnostic token leaked into Detail")
	}

	// Verify Control Center audit failure blocks sensitive mutation fail-closed.
	cc, err := newControlCenterServer("127.0.0.1:43212", pubSrv.URL, k, keyID, ops)
	if err != nil {
		t.Fatalf("newControlCenterServer: %v", err)
	}
	blockedFile := filepath.Join(t.TempDir(), "not-a-dir")
	_ = os.WriteFile(blockedFile, []byte("x"), 0o600)
	cc.auditPath = filepath.Join(blockedFile, "audit.jsonl")
	if err := cc.audit("test", "target", "attempt"); err == nil {
		t.Fatal("expected audit write to fail when audit parent path is not a directory")
	}
}
