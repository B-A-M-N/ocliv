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
