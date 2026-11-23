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
	polID, _ := MintTrustPolicyID()
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

	code, reg := postDCR(t, srv, "ChatGPT", preset.RedirectURIs)
	if code != http.StatusCreated {
		t.Fatalf("DCR status=%d", code)
	}
	clientID := reg["client_id"].(string)

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
	srv.ServeAuthorize(okRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/oauth/authorize?"+q.Encode(), nil))
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
			srv.ServeAuthorize(rec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/oauth/authorize?"+eq.Encode(), nil))
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
	srv.ServeAuthorize(evilRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/oauth/authorize?"+evilQ.Encode(), nil))
	if evilRec.Code != http.StatusBadRequest || evilRec.Header().Get("Location") != "" {
		t.Fatalf("untrusted redirect_uri must return 400 with no Location header, got %d loc=%q", evilRec.Code, evilRec.Header().Get("Location"))
	}
}

// revokeOnMatchStore wraps SQLStore to deterministically simulate an operator
// running `ocliv untrust` between MatchTrustPolicy() and TryRegisterClientWithTrustPolicy().
type revokeOnMatchStore struct {
	*SQLStore
	revokedOnce bool
}

func (r *revokeOnMatchStore) MatchTrustPolicy(tenant, route string, redirectURIs []string) (*ClientTrustPolicy, error) {
	pol, err := r.SQLStore.MatchTrustPolicy(tenant, route, redirectURIs)
	if err == nil && pol != nil && !r.revokedOnce {
		r.revokedOnce = true
		_, _ = r.SQLStore.RevokeTrustPolicy(tenant, route, pol.ID)
	}
	return pol, err
}

func TestTrustPolicySQLStoreE2EAndRevokeInterleaving(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	sqlStore := NewSQLStore(db)
	preset, _ := LookupTrustPreset("chatgpt")

	// Part A: Full SQLStore E2E (DCR -> direct grant -> authorize with iss -> PKCE token -> audit).
	srv := newTrustTestServer(t, sqlStore, "tenant-sql", "route-sql")
	polID, _ := MintTrustPolicyID()
	if err := sqlStore.CreateTrustPolicy(ClientTrustPolicy{
		ID:           polID,
		TenantID:     "tenant-sql",
		RouteID:      "route-sql",
		OwnerKeyID:   "key-sql",
		Kind:         preset.Kind,
		RedirectURIs: preset.RedirectURIs,
		Enabled:      true,
	}); err != nil {
		t.Fatalf("CreateTrustPolicy: %v", err)
	}

	code, reg := postDCR(t, srv, "ChatGPT", preset.RedirectURIs)
	if code != http.StatusCreated {
		t.Fatalf("SQLStore DCR status=%d", code)
	}
	cid := reg["client_id"].(string)
	g, err := sqlStore.GetGrant(cid, "tenant-sql", "route-sql")
	if err != nil || g.Status != GrantActive || !g.SkipPairing {
		t.Fatalf("expected active direct grant in SQLStore, got %+v err=%v", g, err)
	}

	verifier := "sqlstore-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cid},
		"redirect_uri":          {preset.RedirectURIs[0]},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"sql-st"},
		"resource":              {srv.RouteURL},
		"scope":                 {"mcp:tools"},
	}
	authRec := httptest.NewRecorder()
	srv.ServeAuthorize(authRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/oauth/authorize?"+q.Encode(), nil))
	if authRec.Code != http.StatusFound {
		t.Fatalf("SQLStore authorize status=%d body=%s", authRec.Code, authRec.Body.String())
	}
	loc, _ := url.Parse(authRec.Header().Get("Location"))
	if loc.Query().Get("iss") != srv.IssuerURL {
		t.Fatalf("SQLStore authorize redirect missing iss: %s", loc.String())
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"client_id":     {cid},
		"redirect_uri":  {preset.RedirectURIs[0]},
		"code_verifier": {verifier},
		"resource":      {srv.RouteURL},
	}
	tokReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/oauth/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	srv.ServeToken(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("SQLStore token exchange status=%d body=%s", tokRec.Code, tokRec.Body.String())
	}

	// Part B: Deterministic revoke-before-commit interleaving (TOCTOU regression).
	interleaved := &revokeOnMatchStore{SQLStore: sqlStore}
	srvRace := newTrustTestServer(t, interleaved, "tenant-sql", "route-sql")
	code, reg2 := postDCR(t, srvRace, "ChatGPT-Race", preset.RedirectURIs)
	if code != http.StatusCreated {
		t.Fatalf("interleaved DCR status=%d, want 201 pending fallback", code)
	}
	cid2 := reg2["client_id"].(string)
	g2, err := sqlStore.GetGrant(cid2, "tenant-sql", "route-sql")
	if err != nil {
		t.Fatalf("GetGrant interleaved: %v", err)
	}
	if g2.Status != GrantPending || g2.SkipPairing {
		t.Fatalf("revoked policy during DCR must fall back to pending, got status=%s skip_pairing=%v", g2.Status, g2.SkipPairing)
	}
	// Verify no authz-auto-approve audit event was recorded for cid2.
	audits, err := sqlStore.ListAuthzAudit(20)
	if err != nil {
		t.Fatalf("ListAuthzAudit: %v", err)
	}
	for _, a := range audits {
		if a.ClientID == cid2 && a.Action == "authz-auto-approve" {
			t.Fatalf("unexpected authz-auto-approve audit for revoked-policy client %s", cid2)
		}
	}
}
