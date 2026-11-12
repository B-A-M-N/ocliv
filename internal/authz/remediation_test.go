package authz

// Failing-first regressions for the post-review remediation. These describe
// the required trust model; they fail against the pre-fix implementation.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// An approved public client_id must NOT by itself be enough to obtain an
// authorization code. The operator's approval is bound to a pairing secret
// that only the intended client holder receives out of band.
func TestServeAuthorizeRequiresPairingSecret(t *testing.T) {
	s, issuer, store := newTestServer(t)
	_ = issuer
	clientID := "client-pair"
	if err := store.RegisterClient(Client{ID: clientID, Name: "pair",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGrant(Grant{ClientID: clientID, Tenant: "tenant-test",
		Route: "r-test", Status: GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	authorize := func(pairing string) *httptest.ResponseRecorder {
		q := url.Values{}
		q.Set("client_id", clientID)
		q.Set("redirect_uri", "http://127.0.0.1:59999/cb")
		q.Set("response_type", "code")
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
		if pairing != "" {
			q.Set("pairing_code", pairing)
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		s.ServeAuthorize(rec, req)
		return rec
	}

	// No pairing code: no authorization code may be issued.
	rec := authorize("")
	if rec.Code == http.StatusFound {
		t.Fatalf("authorize issued a redirect without the pairing secret (code %d)", rec.Code)
	}

	// A wrong pairing code is equally refused.
	if rec := authorize("wrong-pairing-secret"); rec.Code == http.StatusFound {
		t.Fatal("authorize issued a redirect with a WRONG pairing secret")
	}

	// The operator's pairing secret is required and sufficient.
	secret := "pairing-secret-value"
	if err := store.SetPairingSecret(clientID, "tenant-test", "r-test", secret); err != nil {
		t.Fatalf("set pairing secret: %v", err)
	}
	rec = authorize(secret)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize with the correct pairing secret = %d, want 302 (body %q)", rec.Code, rec.Body.String())
	}
}

// A revoked token must be denied at admission while unrelated clients keep
// working. ServeRevoke previously returned 200 without revoking anything.
func TestServeRevokeInvalidatesToken(t *testing.T) {
	s, issuer, store := newTestServer(t)
	clientA, clientB := "client-rev-a", "client-rev-b"
	for _, c := range []string{clientA, clientB} {
		if err := store.RegisterClient(Client{ID: c, Name: c,
			RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := store.CreateGrant(Grant{ClientID: c, Tenant: "tenant-test", Route: "r-test",
			Status: GrantActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	secretA, secretB := "secret-a", "secret-b"
	if err := store.SetPairingSecret(clientA, "tenant-test", "r-test", secretA); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPairingSecret(clientB, "tenant-test", "r-test", secretB); err != nil {
		t.Fatal(err)
	}

	mint := func(clientID string) string {
		tok, err := issuer.Mint(TokenClaims{Issuer: s.IssuerURL, Subject: clientID,
			Audience: s.RouteURL, Tenant: "tenant-test", Route: "r-test",
			Expiry: time.Now().Add(time.Hour).Unix(), ID: clientID + "-jti"})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	tokA, tokB := mint(clientA), mint(clientB)

	authz := NewAuthorizer(issuer, store)
	call := func(tok string) error {
		req := httptest.NewRequest(http.MethodPost, s.RouteURL, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		return authz.Authorize(req, s.RouteURL, s.IssuerURL, "tenant-test", "r-test")
	}
	if err := call(tokA); err != nil {
		t.Fatalf("pre-revocation A denied: %v", err)
	}

	// Revoke A's token through the advertised OAuth revocation endpoint.
	form := url.Values{}
	form.Set("token", tokA)
	form.Set("token_type_hint", "access_token")
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeRevoke(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d, want 200", rec.Code)
	}

	if err := call(tokA); err == nil {
		t.Fatal("revoked token A still authorizes")
	}
	if err := call(tokB); err != nil {
		t.Fatalf("unrelated token B denied after revoking A: %v", err)
	}
}
