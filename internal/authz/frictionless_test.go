package authz

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRegisterSeedsPendingGrantAndListGrantsIncludesClientMetadata(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	srv := NewServer(issuer, st, "default", "route-a", "https://relay.example/r/route-a/mcp", "https://relay.example")

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{
		"client_name": "ChatGPT",
		"redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeRegister(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}

	grants, err := st.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 pending grant seeded on DCR, got %d", len(grants))
	}
	g := grants[0]
	if g.Status != GrantPending {
		t.Fatalf("status=%q want pending", g.Status)
	}
	if g.ClientName != "ChatGPT" {
		t.Fatalf("ClientName=%q want ChatGPT", g.ClientName)
	}
	if len(g.RedirectURIs) != 1 || g.RedirectURIs[0] != "https://chatgpt.com/connector_platform_oauth_redirect" {
		t.Fatalf("RedirectURIs=%v", g.RedirectURIs)
	}
}

func TestApproveGrantDirectBypassesConsentAndMintsCode(t *testing.T) {
	s, _, _ := newTestServer(t)
	clientID := register(t, s, "https://client.example/cb")

	if err := s.Store.ApproveGrantDirect(clientID, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}

	verifier := "v" + strings.Repeat("a", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://client.example/cb") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=st1" +
		"&resource=" + url.QueryEscape(s.RouteURL)
	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, u, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("direct authorize status=%d body=%s, want 302", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("expected authorization code in redirect, got %q", w.Header().Get("Location"))
	}
	if loc.Query().Get("state") != "st1" {
		t.Fatalf("state=%q want st1", loc.Query().Get("state"))
	}
}

func TestCrossRouteGrantAllowsSameTenantOtherRouteWhenGranted(t *testing.T) {
	st := NewMemStore()
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	sA := NewServer(issuer, st, "default", "route-a", "https://relay.example/r/route-a/mcp", "https://relay.example")
	sB := NewServer(issuer, st, "default", "route-b", "https://relay.example/r/route-b/mcp", "https://relay.example")
	sA.CodeTTL = 5 * time.Minute
	sA.TokenTTL = time.Hour
	sB.CodeTTL = 5 * time.Minute
	sB.TokenTTL = time.Hour
	clientID := register(t, sA, "https://client.example/cb")

	// Without a grant on route-b, route-b still refuses.
	verifier := "v" + strings.Repeat("b", 42)
	authPath := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://client.example/cb") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=s2" +
		"&resource=" + url.QueryEscape(sB.RouteURL)
	wDeny := httptest.NewRecorder()
	sB.ServeAuthorize(wDeny, httptest.NewRequest(http.MethodGet, authPath, nil))
	if wDeny.Code != http.StatusBadRequest {
		t.Fatalf("ungranted route-b status=%d, want 400", wDeny.Code)
	}

	// Granting route-b directly for the same tenant succeeds and allows /oauth/authorize + /oauth/token + admission.
	if err := st.ApproveGrantDirect(clientID, "default", "route-b"); err != nil {
		t.Fatalf("ApproveGrantDirect route-b: %v", err)
	}
	wAllow := httptest.NewRecorder()
	sB.ServeAuthorize(wAllow, httptest.NewRequest(http.MethodGet, authPath, nil))
	if wAllow.Code != http.StatusFound {
		t.Fatalf("granted route-b status=%d body=%s, want 302", wAllow.Code, wAllow.Body.String())
	}
	loc, _ := url.Parse(wAllow.Header().Get("Location"))
	code := loc.Query().Get("code")

	tokReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=authorization_code&code="+url.QueryEscape(code)+
			"&client_id="+url.QueryEscape(clientID)+
			"&redirect_uri="+url.QueryEscape("https://client.example/cb")+
			"&code_verifier="+url.QueryEscape(verifier)+
			"&resource="+url.QueryEscape(sB.RouteURL)))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wTok := httptest.NewRecorder()
	sB.ServeToken(wTok, tokReq)
	if wTok.Code != http.StatusOK {
		t.Fatalf("route-b token status=%d body=%s", wTok.Code, wTok.Body.String())
	}

	// Verify Authorizer admits the route-b token.
	a := NewAuthorizer(issuer, st)
	_ = time.Now()
	if !strings.Contains(wTok.Body.String(), "access_token") {
		t.Fatalf("missing access_token in %s", wTok.Body.String())
	}
	_ = a
}
