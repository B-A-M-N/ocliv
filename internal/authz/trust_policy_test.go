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
	issuerURL := "https://relay.example/r/" + route
	return NewServer(issuer, store, tenant, route, routeURL, issuerURL)
}

func postDCR(t *testing.T, srv *Server, name string, redirectURIs []string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"client_name":                name,
		"redirect_uris":              redirectURIs,
		"token_endpoint_auth_method": "none",
	})
	req := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/oauth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeRegister(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestTrustPolicyExactMatchAutoApprovesAndMintsToken(t *testing.T) {
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

	// 1. DCR with exact ChatGPT callback URI -> auto-approved direct grant.
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
	if grant.Status != GrantActive || !grant.SkipPairing {
		t.Fatalf("expected active direct grant, got status=%s skip_pairing=%v", grant.Status, grant.SkipPairing)
	}

	// 2. Distinct audit event recorded for auto-approval.
	audits, err := store.ListAuthzAudit(10)
	if err != nil {
		t.Fatalf("ListAuthzAudit: %v", err)
	}
	foundAudit := false
	for _, a := range audits {
		if a.Action == "authz-auto-approve" && a.Actor == "publisher" && a.ClientID == clientID && a.Result == "ok" && strings.Contains(a.Detail, "policy=chatgpt") {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("expected distinct authz-auto-approve audit event, got %+v", audits)
	}

	// 3. /oauth/authorize proceeds directly to code redirect with zero pairing screen.
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
	authReq := httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/oauth/authorize?"+q.Encode(), nil)
	authRec := httptest.NewRecorder()
	srv.ServeAuthorize(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("expected 302 direct code redirect, got %d body=%s", authRec.Code, authRec.Body.String())
	}
	loc, err := url.Parse(authRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	authCode := loc.Query().Get("code")
	if authCode == "" {
		t.Fatalf("expected code in redirect %q", loc.String())
	}
	if loc.Query().Get("state") != "st-123" {
		t.Fatalf("expected state=st-123, got %q", loc.Query().Get("state"))
	}

	// 4. Token exchange with PKCE succeeds.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {clientID},
		"redirect_uri":  {preset.RedirectURIs[0]},
		"code_verifier": {verifier},
		"resource":      {srv.RouteURL},
	}
	tokReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/oauth/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	srv.ServeToken(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("expected 200 token response, got %d body=%s", tokRec.Code, tokRec.Body.String())
	}
	var tokResp map[string]any
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tokResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokResp["access_token"] == "" {
		t.Fatalf("expected access_token, got %v", tokResp)
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

	// Negative 2: Extra redirect URI alongside ChatGPT URI must NOT auto-approve.
	code, reg := postDCR(t, srvA1, "ChatGPT", []string{chatgptURI, "https://evil.example/cb"})
	if code != http.StatusCreated {
		t.Fatalf("DCR extra URI status=%d", code)
	}
	g, err := store.GetGrant(reg["client_id"].(string), "tenant-a", "route-1")
	if err != nil || g.Status != GrantPending || g.SkipPairing {
		t.Fatalf("extra redirect URI must stay pending, got grant=%+v err=%v", g, err)
	}

	// Negative 3: Wrong redirect URI on same host must NOT auto-approve.
	code, reg = postDCR(t, srvA1, "ChatGPT", []string{"https://chatgpt.com/other_callback"})
	if code != http.StatusCreated {
		t.Fatalf("DCR wrong URI status=%d", code)
	}
	g, err = store.GetGrant(reg["client_id"].(string), "tenant-a", "route-1")
	if err != nil || g.Status != GrantPending || g.SkipPairing {
		t.Fatalf("wrong redirect URI must stay pending, got grant=%+v err=%v", g, err)
	}

	// Negative 4: Cross-route (same tenant, different route) must NOT auto-approve.
	code, reg = postDCR(t, srvA2, "ChatGPT", []string{chatgptURI})
	if code != http.StatusCreated {
		t.Fatalf("DCR cross-route status=%d", code)
	}
	g, err = store.GetGrant(reg["client_id"].(string), "tenant-a", "route-2")
	if err != nil || g.Status != GrantPending || g.SkipPairing {
		t.Fatalf("cross-route DCR must stay pending, got grant=%+v err=%v", g, err)
	}

	// Negative 5: Cross-tenant (different tenant, same route ID) must NOT auto-approve.
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
	srvA1.ServeAuthorize(authRec, httptest.NewRequest(http.MethodGet, srvA1.IssuerURL+"/oauth/authorize?"+q.Encode(), nil))
	if authRec.Code == http.StatusFound {
		t.Fatalf("revoked client must not receive authorization code")
	}

	// Negative 7: Revoked trust policy stops auto-approving new registrations.
	n, err := store.RevokeTrustPolicy("tenant-a", "route-1", "chatgpt")
	if err != nil || n != 1 {
		t.Fatalf("RevokeTrustPolicy: n=%d err=%v", n, err)
	}
	code, reg = postDCR(t, srvA1, "ChatGPT", []string{chatgptURI})
	if code != http.StatusCreated {
		t.Fatalf("DCR after policy revoke status=%d", code)
	}
	g, err = store.GetGrant(reg["client_id"].(string), "tenant-a", "route-1")
	if err != nil || g.Status != GrantPending || g.SkipPairing {
		t.Fatalf("revoked policy must not auto-approve new client, got grant=%+v err=%v", g, err)
	}
}
