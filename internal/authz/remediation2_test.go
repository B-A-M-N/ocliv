package authz

// Failing-first regressions for the second remediation pass.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- Item 1: consent page instead of a credential in the URL -------------

// The pairing secret must never be an authorization-request parameter. A
// pending approval renders a standards-compatible consent page, and the
// secret is submitted by POST against a one-time, expiring,
// transaction-bound challenge.
func TestConsentPageNotURLCredential(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-consent"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	params.Set("response_type", "code")
	params.Set("code_challenge", CodeChallengeS256("v"))
	params.Set("code_challenge_method", "S256")
	params.Set("resource", s.RouteURL)
	params.Set("state", "xyz")

	// A pending approval must render a consent page, not redirect and not
	// accept a pairing_code query parameter.
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()
	s.ServeAuthorize(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pending authorize status=%d, want 200 consent page", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("pending authorize must not redirect")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/oauth/consent") {
		t.Fatalf("consent page has no consent form: %q", body)
	}
	// The secret must not be accepted as a URL parameter.
	req2 := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode()+"&pairing_code=anything", nil)
	rec2 := httptest.NewRecorder()
	s.ServeAuthorize(rec2, req2)
	if rec2.Header().Get("Location") != "" {
		t.Fatal("pairing_code in the URL must not authorize anything")
	}

	// Extract the challenge from the page and POST the secret.
	challenge := extractChallenge(t, body)
	secret := "operator-secret"
	if err := store.SetPairingSecret(clientID, "tenant-test", "r-test", secret); err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("challenge", challenge)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	form.Set("code_challenge", CodeChallengeS256("v"))
	form.Set("code_challenge_method", "S256")
	form.Set("resource", s.RouteURL)
	form.Set("state", "xyz")
	form.Set("pairing_secret", secret)

	req3 := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec3 := httptest.NewRecorder()
	s.ServeConsent(rec3, req3)
	if rec3.Code != http.StatusFound {
		t.Fatalf("consent POST status=%d body=%q, want 302", rec3.Code, rec3.Body.String())
	}
	if !strings.HasPrefix(rec3.Header().Get("Location"), "http://127.0.0.1:59999/cb?code=") {
		t.Fatalf("consent redirect=%q", rec3.Header().Get("Location"))
	}

	// The challenge is one-time.
	req4 := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec4 := httptest.NewRecorder()
	s.ServeConsent(rec4, req4)
	if rec4.Code == http.StatusFound {
		t.Fatal("consent challenge replayed")
	}
}

// An already-consented (ACTIVE) grant must complete the normal OAuth flow
// with NO Ocliv-specific parameters.
func TestActiveGrantNeedsNoOclivParams(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-normal"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(Grant{ClientID: clientID, Tenant: "tenant-test", Route: "r-test",
		Status: GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Standard authorization request only: client_id, redirect_uri,
	// response_type, code_challenge, code_challenge_method, state, resource.
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	q.Set("response_type", "code")
	q.Set("code_challenge", CodeChallengeS256("v"))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", s.RouteURL)
	q.Set("state", "s")
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	s.ServeAuthorize(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("ordinary OAuth authorize status=%d, want 302", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "http://127.0.0.1:59999/cb?code=") {
		t.Fatalf("redirect=%q", rec.Header().Get("Location"))
	}
}

// --- Item 2: client-level revocation --------------------------------------

func TestRevokedClientCannotUseExistingToken(t *testing.T) {
	s, issuer, store := newTestServer(t)
	clientID := "client-revoked"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(Grant{ClientID: clientID, Tenant: "tenant-test", Route: "r-test",
		Status: GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tok, err := issuer.Mint(TokenClaims{Issuer: s.IssuerURL, Subject: clientID,
		Audience: s.RouteURL, Tenant: "tenant-test", Route: "r-test",
		Expiry: time.Now().Add(time.Hour).Unix(), ID: "jti-revoked"})
	if err != nil {
		t.Fatal(err)
	}
	authz := NewAuthorizer(issuer, store)
	call := func() error {
		req := httptest.NewRequest(http.MethodPost, s.RouteURL, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		return authz.Authorize(req, s.RouteURL, s.IssuerURL, "tenant-test", "r-test")
	}
	if err := call(); err != nil {
		t.Fatalf("pre-revocation denied: %v", err)
	}
	if err := store.RevokeClient(clientID); err != nil {
		t.Fatal(err)
	}
	if err := call(); err == nil {
		t.Fatal("revoked client's existing token still authorizes")
	}
}

func TestRevokedClientCannotRedeemCode(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-revoked-code"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(Grant{ClientID: clientID, Tenant: "tenant-test", Route: "r-test",
		Status: GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	code := "code-to-redeem"
	if err := store.CreateCode(Code{Code: code, ClientID: clientID, Tenant: "tenant-test",
		Route: "r-test", RedirectURI: "http://127.0.0.1:59999/cb",
		Challenge: CodeChallengeS256("v"), ChallengeMethod: "S256",
		ExpiresAt: time.Now().Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeClient(clientID); err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	form.Set("code_verifier", "v")
	form.Set("resource", s.RouteURL)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeToken(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("revoked client redeemed a code: %s", rec.Body.String())
	}
}

// --- Item 3: JTI required, revocation scoped ------------------------------

func TestMissingJTITokenRejected(t *testing.T) {
	s, issuer, store := newTestServer(t)
	clientID := "client-nojti"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(Grant{ClientID: clientID, Tenant: "tenant-test", Route: "r-test",
		Status: GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tok, err := issuer.Mint(TokenClaims{Issuer: s.IssuerURL, Subject: clientID,
		Audience: s.RouteURL, Tenant: "tenant-test", Route: "r-test",
		Expiry: time.Now().Add(time.Hour).Unix()}) // no ID
	if err != nil {
		t.Fatal(err)
	}
	authz := NewAuthorizer(issuer, store)
	req := httptest.NewRequest(http.MethodPost, s.RouteURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if err := authz.Authorize(req, s.RouteURL, s.IssuerURL, "tenant-test", "r-test"); err == nil {
		t.Fatal("token without a jti was accepted at admission")
	}
}

func TestTokenRevocationScopedToTenantAndRoute(t *testing.T) {
	_, _, store := newTestServer(t)
	if err := store.RevokeToken("shared-jti", "c", "tenant-a", "route-a"); err != nil {
		t.Fatal(err)
	}
	revoked, err := store.IsTokenRevoked("shared-jti", "tenant-a", "route-a")
	if err != nil || !revoked {
		t.Fatalf("same tenant+route revoked=%v err=%v, want true", revoked, err)
	}
	revoked, err = store.IsTokenRevoked("shared-jti", "tenant-b", "route-a")
	if err != nil || revoked {
		t.Fatalf("other tenant revoked=%v err=%v, want false", revoked, err)
	}
	revoked, err = store.IsTokenRevoked("shared-jti", "tenant-a", "route-b")
	if err != nil || revoked {
		t.Fatalf("other route revoked=%v err=%v, want false", revoked, err)
	}
}

// --- Item 5: resource parameter -------------------------------------------

func TestResourceParameterMustMatchRoute(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-resource"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(Grant{ClientID: clientID, Tenant: "tenant-test", Route: "r-test",
		Status: GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	authorize := func(resource string) int {
		q := url.Values{}
		q.Set("client_id", clientID)
		q.Set("redirect_uri", "http://127.0.0.1:59999/cb")
		q.Set("response_type", "code")
		q.Set("code_challenge", CodeChallengeS256("v"))
		q.Set("code_challenge_method", "S256")
		if resource != "" {
			q.Set("resource", resource)
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		s.ServeAuthorize(rec, req)
		return rec.Code
	}
	// The canonical resource is required (MCP authorization spec) and must
	// match the route exactly.
	if code := authorize(""); code == http.StatusFound {
		t.Fatal("authorize without resource was allowed")
	}
	if code := authorize("https://evil.example/r/x/mcp"); code == http.StatusFound {
		t.Fatal("authorize with a foreign resource was allowed")
	}
	if code := authorize(s.RouteURL); code != http.StatusFound {
		t.Fatalf("authorize with the canonical resource = %d, want 302", code)
	}
}

func extractChallenge(t *testing.T, page string) string {
	t.Helper()
	// The consent form carries <input type="hidden" name="challenge" value="...">.
	marker := `name="challenge" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no challenge field in consent page: %q", page)
	}
	rest := page[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated challenge value: %q", rest)
	}
	return rest[:j]
}

var _ = json.Marshal
