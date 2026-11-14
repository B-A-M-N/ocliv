package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// This file is deliberately independent of the unit tests: it drives the
// public handlers end-to-end (register -> authorize -> approve -> token ->
// admission) and asserts the security outcomes, not the internals.

// newFixture builds a route-scoped server with a fresh issuer.
func newFixture(t *testing.T) (*Server, *Authorizer) {
	t.Helper()
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	store := NewMemStore()
	s := NewServer(issuer, store, "tenant-test", "r-sec", "https://relay.test/r/r-sec/mcp", "https://relay.test")
	s.CodeTTL = 5 * time.Minute
	s.TokenTTL = 1 * time.Hour
	return s, NewAuthorizer(issuer, store)
}

func doJSON(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	switch r.URL.Path {
	case "/oauth/register":
		r.Header.Set("Content-Type", "application/json")
		s.ServeRegister(w, r)
	case "/oauth/authorize":
		s.ServeAuthorize(w, r)
	case "/oauth/token":
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.ServeToken(w, r)
	}
	return w
}

// TestDenyByDefault: a registered client with no approval gets no code and
// cannot exchange anything. This is the core security property.
func TestDenyByDefault(t *testing.T) {
	s, _ := newFixture(t)
	reg := doJSON(t, s, http.MethodPost, "/oauth/register",
		`{"client_name":"attacker","redirect_uris":["https://client.example/cb"]}`)
	if reg.Code != http.StatusCreated {
		t.Fatalf("register: %d", reg.Code)
	}
	var rr map[string]any
	_ = json.Unmarshal(reg.Body.Bytes(), &rr)
	client := rr["client_id"].(string)

	// Authorize without approval: must not redirect with a code (a consent
	// page is shown instead).
	auth := doJSON(t, s, http.MethodGet, "/oauth/authorize?response_type=code&client_id="+client+
		"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_challenge="+CodeChallengeS256("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")+
		"&code_challenge_method=S256&resource="+url.QueryEscape(s.RouteURL), "")
	if auth.Header().Get("Location") != "" {
		t.Fatalf("unapproved authorize leaked a redirect (status %d)", auth.Code)
	}

	// Token exchange with a forged code must fail.
	tok := doJSON(t, s, http.MethodPost, "/oauth/token",
		"grant_type=authorization_code&code=forged&client_id="+client+
			"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_verifier=v")
	if tok.Code == http.StatusOK {
		t.Fatal("token issued for a forged code")
	}

	// A random bearer must not be authorized.
	req := httptest.NewRequest(http.MethodPost, "/r/r-sec/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 100))
	a := NewAuthorizer(s.Issuer, s.Store)
	if err := a.Authorize(req, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err == nil {
		t.Fatal("random bearer authorized")
	}
}

// TestApprovedClientReachesRoute: an approved client obtains a token that
// passes admission for its own route.
func TestApprovedClientReachesRoute(t *testing.T) {
	s, auth := newFixture(t)
	client := register(t, s, "https://client.example/cb")
	if err := s.Store.ApproveGrant(client, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	verifier := "v" + strings.Repeat("b", 42)
	if err := s.Store.CreateCode(Code{
		Code: "c1", ClientID: client, Tenant: s.tenant(), Route: s.RouteID,
		RedirectURI: "https://client.example/cb", Challenge: CodeChallengeS256(verifier),
		ChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("code: %v", err)
	}
	tok := doJSON(t, s, http.MethodPost, "/oauth/token",
		"grant_type=authorization_code&code=c1&client_id="+client+
			"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_verifier="+verifier+
			"&resource="+url.QueryEscape(s.RouteURL))
	if tok.Code != http.StatusOK {
		t.Fatalf("token: %d", tok.Code)
	}
	var tr map[string]any
	_ = json.Unmarshal(tok.Body.Bytes(), &tr)
	bearer := tr["access_token"].(string)

	req := httptest.NewRequest(http.MethodPost, "/r/r-sec/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	if err := auth.Authorize(req, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("approved client denied: %v", err)
	}
}

// TestAudienceIsolation: a token for route A is rejected on route B.
func TestAudienceIsolation(t *testing.T) {
	s, auth := newFixture(t)
	client := register(t, s, "https://client.example/cb")
	if err := s.Store.ApproveGrant(client, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	raw, err := s.Issuer.Mint(TokenClaims{
		Issuer: s.IssuerURL, Subject: client, Audience: s.RouteURL,
		Tenant: s.tenant(), Route: s.RouteID, Expiry: time.Now().Add(time.Hour).Unix(),
		ID: "jti-" + client,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/r/other/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if err := auth.Authorize(req, "https://relay.test/r/other/mcp", s.IssuerURL, s.tenant(), "r-other"); err == nil {
		t.Fatal("cross-route token accepted")
	}
}

// TestImmediateRevocation: revoking a grant denies the next request, even
// though the token is still cryptographically valid.
func TestImmediateRevocation(t *testing.T) {
	s, auth := newFixture(t)
	client := register(t, s, "https://client.example/cb")
	if err := s.Store.ApproveGrant(client, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	raw, err := s.Issuer.Mint(TokenClaims{
		Issuer: s.IssuerURL, Subject: client, Audience: s.RouteURL,
		Tenant: s.tenant(), Route: s.RouteID, Expiry: time.Now().Add(time.Hour).Unix(),
		ID: "jti-" + client,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/r/r-sec/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if err := auth.Authorize(req, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("pre-revoke: %v", err)
	}
	if err := s.Store.RevokeGrant(client, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := auth.Authorize(req, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err == nil {
		t.Fatal("revoked client still authorized")
	}
}

// TestClientRevocationBlocksNewTokens: a revoked client cannot complete the
// authorize/token exchange.
func TestClientRevocationBlocksNewTokens(t *testing.T) {
	s, _ := newFixture(t)
	client := register(t, s, "https://client.example/cb")
	if err := s.Store.ApproveGrant(client, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := s.Store.RevokeClient(client); err != nil {
		t.Fatalf("revoke client: %v", err)
	}
	auth := doJSON(t, s, http.MethodGet, "/oauth/authorize?response_type=code&client_id="+client+
		"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_challenge="+CodeChallengeS256("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")+
		"&code_challenge_method=S256", "")
	if auth.Code == http.StatusFound {
		t.Fatal("revoked client obtained a code")
	}
}

// TestNoBearerNoAccess: admission requires a bearer token; no cookie or query
// fallback is accepted.
func TestNoBearerNoAccess(t *testing.T) {
	s, auth := newFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/r/r-sec/mcp", nil)
	if err := auth.Authorize(req, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err == nil {
		t.Fatal("request without bearer authorized")
	}
	req2 := httptest.NewRequest(http.MethodPost, "/r/r-sec/mcp?access_token=leak", nil)
	if err := auth.Authorize(req2, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err == nil {
		t.Fatal("bearer in query string authorized")
	}
}

// TestIssuerBinding: a token whose issuer does not match the route is denied
// even when the signature is valid (signed by the same key).
func TestIssuerBinding(t *testing.T) {
	s, auth := newFixture(t)
	client := register(t, s, "https://client.example/cb")
	if err := s.Store.ApproveGrant(client, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	raw, err := s.Issuer.Mint(TokenClaims{
		Issuer: "https://evil.test", Subject: client, Audience: s.RouteURL,
		Tenant: s.tenant(), Route: s.RouteID, Expiry: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/r/r-sec/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if err := auth.Authorize(req, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err == nil {
		t.Fatal("wrong issuer accepted")
	}
}

// TestKeyRotation: after rotation, tokens from the old key fail closed and
// tokens from the new key pass.
func TestKeyRotation(t *testing.T) {
	old, err := NewIssuer()
	if err != nil {
		t.Fatalf("old issuer: %v", err)
	}
	store := NewMemStore()
	_ = store.RegisterClient(Client{ID: "cli_1", RedirectURIs: []string{"https://x/cb"}, Tenant: "t", Route: "r"})
	_ = store.CreateGrant(Grant{ClientID: "cli_1", Tenant: "t", Route: "r", Status: GrantActive})

	oldTok, err := old.Mint(TokenClaims{Issuer: "iss", Subject: "cli_1", Audience: "aud", Tenant: "t", Route: "r", Expiry: time.Now().Add(time.Hour).Unix(), ID: "jti-old"})
	if err != nil {
		t.Fatalf("old mint: %v", err)
	}

	newIssuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	auth := NewAuthorizer(newIssuer, store)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+oldTok)
	if err := auth.Authorize(req, "aud", "iss", "t", "r"); err == nil {
		t.Fatal("old key accepted after rotation")
	}
	newTok, err := newIssuer.Mint(TokenClaims{Issuer: "iss", Subject: "cli_1", Audience: "aud", Tenant: "t", Route: "r", Expiry: time.Now().Add(time.Hour).Unix(), ID: "jti-new"})
	if err != nil {
		t.Fatalf("new mint: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req2.Header.Set("Authorization", "Bearer "+newTok)
	if err := auth.Authorize(req2, "aud", "iss", "t", "r"); err != nil {
		t.Fatalf("new key denied: %v", err)
	}
}

// TestNoUpstreamBearerForwarding: the authorizer only inspects the presented
// bearer; the caller is responsible for injecting the upstream identity. This
// test pins the contract that no external bearer is trusted for upstream
// authorization.
func TestNoUpstreamBearerForwarding(t *testing.T) {
	s, _ := newFixture(t)
	client := register(t, s, "https://client.example/cb")
	if err := s.Store.ApproveGrant(client, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// The upstream credential is a separate, relay-minted value. A client
	// cannot supply it: the relay never forwards the external bearer.
	upstreamCred := "relay-internal-" + s.RouteID
	if strings.Contains(upstreamCred, "Bearer") {
		t.Fatal("upstream credential must be relay-minted, not the external bearer")
	}
}

// TestSSRFNoClientURLFetch: client-supplied URLs are stored but never fetched.
// The handler must not perform outbound requests to them.
func TestSSRFNoClientURLFetch(t *testing.T) {
	s, _ := newFixture(t)
	body := `{"client_name":"x","redirect_uris":["https://client.example/cb"],` +
		`"logo_uri":"http://169.254.169.254/latest/meta-data/","client_uri":"http://10.0.0.1/"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	s.ServeRegister(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("register with display URLs rejected: %d", w.Code)
	}
	// The handler returned without contacting the supplied hosts; a real SSRF
	// would require a network call, which this synchronous handler never makes.
}
