package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTrustTestServer(t *testing.T, store Store, tenant, route string) *Server {
	t.Helper()
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	routeURL := "https://relay.example/r/" + route + "/mcp"
	issuerURL := "https://relay.example/r/" + route + "/oauth"
	return NewServer(issuer, store, tenant, route, routeURL, issuerURL)
}

func postDCR(t *testing.T, srv *Server, name string, redirectURIs []string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"client_name":                name,
		"redirect_uris":              redirectURIs,
		"token_endpoint_auth_method": "none",
	})
	req := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeRegister(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// OCL-005 & OCL-007: Matching a redirect-URI trust policy alone MUST NOT create
// an active grant at registration time or authorize a private route without
// resource-owner authentication.
func TestRedirectTrustPolicyAloneCannotAuthorizePrivateRoute(t *testing.T) {
	store := NewMemStore()
	srv := newTrustTestServer(t, store, "tenant-a", "route-1")

	preset, ok := LookupTrustPreset("chatgpt")
	if !ok {
		t.Fatal("expected built-in chatgpt trust preset")
	}
	polID, err := MintTrustPolicyID()
	if err != nil {
		t.Fatalf("MintTrustPolicyID: %v", err)
	}
	if err := store.CreateTrustPolicy(ClientTrustPolicy{
		ID:           polID,
		TenantID:     "tenant-a",
		RouteID:      "route-1",
		OwnerKeyID:   "key-owner",
		Kind:         preset.Kind,
		RedirectURIs: preset.RedirectURIs,
		Enabled:      true,
	}); err != nil {
		t.Fatalf("CreateTrustPolicy: %v", err)
	}

	// 1. DCR with exact ChatGPT callback URI -> remains PENDING (never auto-active).
	code, reg := postDCR(t, srv, "ChatGPT", preset.RedirectURIs)
	if code != http.StatusCreated {
		t.Fatalf("DCR status=%d body=%v", code, reg)
	}
	clientID, _ := reg["client_id"].(string)
	if clientID == "" {
		t.Fatalf("missing client_id: %v", reg)
	}

	grant, err := store.GetGrant(clientID, "tenant-a", "route-1")
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if grant.Status != GrantPending || grant.SkipPairing {
		t.Fatalf("redirect-URI DCR must remain pending without resource-owner auth, got status=%s skip_pairing=%v", grant.Status, grant.SkipPairing)
	}

	// 2. /oauth/authorize without federated OIDC or explicit operator direct
	// approval MUST NOT issue an authorization code; it renders the consent gate.
	verifier := "test-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {preset.RedirectURIs[0]},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"st-123"},
		"resource":              {srv.RouteURL},
		"scope":                 {"mcp:tools"},
	}
	authReq := httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+q.Encode(), nil)
	authRec := httptest.NewRecorder()
	srv.ServeAuthorize(authRec, authReq)
	if authRec.Code != http.StatusOK || authRec.Header().Get("Location") != "" {
		t.Fatalf("matching redirect URI alone must not issue code redirect: status=%d loc=%q", authRec.Code, authRec.Header().Get("Location"))
	}
}

func TestTrustPolicyNegativeBoundaries(t *testing.T) {
	store := NewMemStore()
	srvA1 := newTrustTestServer(t, store, "tenant-a", "route-1")
	srvA2 := newTrustTestServer(t, store, "tenant-a", "route-2")
	srvB1 := newTrustTestServer(t, store, "tenant-b", "route-1")

	chatgptURI := "https://chatgpt.com/connector_platform_oauth_redirect"
	polID, _ := MintTrustPolicyID()
	if err := store.CreateTrustPolicy(ClientTrustPolicy{
		ID:           polID,
		TenantID:     "tenant-a",
		RouteID:      "route-1",
		OwnerKeyID:   "key-owner",
		Kind:         "chatgpt",
		RedirectURIs: []string{chatgptURI},
		Enabled:      true,
	}); err != nil {
		t.Fatalf("CreateTrustPolicy: %v", err)
	}

	// Negative 1: HTTP redirect URI cannot be stored in a trust policy.
	if err := store.CreateTrustPolicy(ClientTrustPolicy{
		ID:           "tp_http",
		TenantID:     "tenant-a",
		RouteID:      "route-1",
		OwnerKeyID:   "key-owner",
		Kind:         "custom",
		RedirectURIs: []string{"http://chatgpt.com/connector_platform_oauth_redirect"},
		Enabled:      true,
	}); err == nil {
		t.Fatal("expected HTTP trust policy to be rejected")
	}

	// Negative 2: Extra redirect URI alongside ChatGPT URI must NOT match policy.
	if matched, err := store.MatchTrustPolicy("tenant-a", "route-1", []string{chatgptURI, "https://evil.example/cb"}); err != nil || matched != nil {
		t.Fatalf("extra redirect URI must not match policy, got %+v err=%v", matched, err)
	}

	// Negative 3: Wrong redirect URI on same host must NOT match policy.
	if matched, err := store.MatchTrustPolicy("tenant-a", "route-1", []string{"https://chatgpt.com/other_callback"}); err != nil || matched != nil {
		t.Fatalf("wrong redirect URI must not match policy, got %+v err=%v", matched, err)
	}

	// Negative 4: Cross-route (same tenant, different route) must NOT match.
	code, reg := postDCR(t, srvA2, "ChatGPT", []string{chatgptURI})
	if code != http.StatusCreated {
		t.Fatalf("DCR cross-route status=%d", code)
	}
	g, err := store.GetGrant(reg["client_id"].(string), "tenant-a", "route-2")
	if err != nil || g.Status != GrantPending || g.SkipPairing {
		t.Fatalf("cross-route DCR must stay pending, got grant=%+v err=%v", g, err)
	}

	// Negative 5: Cross-tenant (different tenant, same route ID) must NOT match.
	code, reg = postDCR(t, srvB1, "ChatGPT", []string{chatgptURI})
	if code != http.StatusCreated {
		t.Fatalf("DCR cross-tenant status=%d", code)
	}
	g, err = store.GetGrant(reg["client_id"].(string), "tenant-b", "route-1")
	if err != nil || g.Status != GrantPending || g.SkipPairing {
		t.Fatalf("cross-tenant DCR must stay pending, got grant=%+v err=%v", g, err)
	}

	// Negative 6: Revoked client stays denied even while policy is active.
	code, reg = postDCR(t, srvA1, "ChatGPT", []string{chatgptURI})
	if code != http.StatusCreated {
		t.Fatalf("DCR valid status=%d", code)
	}
	revClientID := reg["client_id"].(string)
	if err := store.RevokeClient(revClientID); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {revClientID},
		"redirect_uri":          {chatgptURI},
		"code_challenge":        {"abc1234567890123456789012345678901234567890"},
		"code_challenge_method": {"S256"},
		"resource":              {srvA1.RouteURL},
	}
	authRec := httptest.NewRecorder()
	srvA1.ServeAuthorize(authRec, httptest.NewRequest(http.MethodGet, srvA1.IssuerURL+"/authorize?"+q.Encode(), nil))
	if authRec.Code == http.StatusFound {
		t.Fatalf("revoked client must not receive authorization code")
	}

	// Negative 7: Revoked trust policy stops matching.
	n, err := store.RevokeTrustPolicy("tenant-a", "route-1", "chatgpt")
	if err != nil || n != 1 {
		t.Fatalf("RevokeTrustPolicy: n=%d err=%v", n, err)
	}
	if matched, err := store.MatchTrustPolicy("tenant-a", "route-1", []string{chatgptURI}); err != nil || matched != nil {
		t.Fatalf("revoked policy must not match, got %+v err=%v", matched, err)
	}
}

func TestRFC9207IssuerMetadataAndAuthorizationResponses(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	store := NewSQLStore(db)
	srv := newTrustTestServer(t, store, "tenant-a", "route-1")

	// 1. Metadata advertises RFC 9207 authorization_response_iss_parameter_supported=true.
	meta := srv.AuthorizationServerMetadata()
	if supported, ok := meta["authorization_response_iss_parameter_supported"].(bool); !ok || !supported {
		t.Fatalf("expected authorization_response_iss_parameter_supported=true, got %v", meta["authorization_response_iss_parameter_supported"])
	}

	preset, _ := LookupTrustPreset("chatgpt")
	code, reg := postDCR(t, srv, "ChatGPT", preset.RedirectURIs)
	if code != http.StatusCreated {
		t.Fatalf("DCR status=%d", code)
	}
	clientID := reg["client_id"].(string)
	// Explicit per-client operator approval unlocks direct code redirect for RFC 9207 test.
	if err := store.ApproveGrantDirect(clientID, "tenant-a", "route-1"); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}

	// 2. Success redirect carries exact iss and state.
	verifier := "rfc9207-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {preset.RedirectURIs[0]},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"st-ok"},
		"resource":              {srv.RouteURL},
		"scope":                 {"mcp:tools"},
	}
	okRec := httptest.NewRecorder()
	srv.ServeAuthorize(okRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+q.Encode(), nil))
	if okRec.Code != http.StatusFound {
		t.Fatalf("expected 302 on success, got %d body=%s", okRec.Code, okRec.Body.String())
	}
	okLoc, _ := url.Parse(okRec.Header().Get("Location"))
	if okLoc.Query().Get("iss") != srv.IssuerURL || okLoc.Query().Get("state") != "st-ok" || okLoc.Query().Get("code") == "" {
		t.Fatalf("success redirect missing RFC 9207 iss/state/code: %s", okLoc.String())
	}

	// 3. OAuth error AFTER client + redirect_uri are verified redirects with error, state, and exact iss.
	for _, tc := range []struct {
		name      string
		mutate    func(url.Values)
		wantError string
	}{
		{
			name:      "missing PKCE",
			mutate:    func(v url.Values) { v.Del("code_challenge"); v.Del("code_challenge_method") },
			wantError: "invalid_request",
		},
		{
			name:      "wrong resource",
			mutate:    func(v url.Values) { v.Set("resource", "https://other.example/r/other/mcp") },
			wantError: "invalid_target",
		},
		{
			name:      "unsupported response_type",
			mutate:    func(v url.Values) { v.Set("response_type", "token") },
			wantError: "unsupported_response_type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eq := url.Values{}
			for k, vs := range q {
				eq[k] = append([]string(nil), vs...)
			}
			eq.Set("state", "st-err")
			tc.mutate(eq)
			rec := httptest.NewRecorder()
			srv.ServeAuthorize(rec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+eq.Encode(), nil))
			if rec.Code != http.StatusFound {
				t.Fatalf("%s: expected 302 error redirect, got %d body=%s", tc.name, rec.Code, rec.Body.String())
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if !strings.HasPrefix(loc.String(), preset.RedirectURIs[0]) {
				t.Fatalf("unexpected redirect target %q", loc.String())
			}
			if loc.Query().Get("error") != tc.wantError {
				t.Fatalf("error=%q, want %q", loc.Query().Get("error"), tc.wantError)
			}
			if loc.Query().Get("state") != "st-err" {
				t.Fatalf("state=%q, want st-err", loc.Query().Get("state"))
			}
			if loc.Query().Get("iss") != srv.IssuerURL {
				t.Fatalf("iss=%q, want %q", loc.Query().Get("iss"), srv.IssuerURL)
			}
		})
	}

	// 4. Errors BEFORE redirect_uri is trusted MUST return local 400 JSON and NEVER redirect.
	evilQ := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://evil.example/steal"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"st-evil"},
		"resource":              {srv.RouteURL},
	}
	evilRec := httptest.NewRecorder()
	srv.ServeAuthorize(evilRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+evilQ.Encode(), nil))
	if evilRec.Code != http.StatusBadRequest || evilRec.Header().Get("Location") != "" {
		t.Fatalf("untrusted redirect_uri must return 400 with no Location header, got %d loc=%q", evilRec.Code, evilRec.Header().Get("Location"))
	}
}
