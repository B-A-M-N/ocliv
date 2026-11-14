package authz

// Failing-first regressions for the 2026-11-14 source review's
// cross-route authorization boundary findings. Each test names the
// boundary it closes and fails against the pre-fix tree.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestCrossRouteRevokePoisonsRouteA (review P1 #1): a token issued for
// route A and presented at route B's /oauth/revoke must NOT consume the
// globally-unique jti with a B-scoped row. Pre-fix, B's insert poisons
// the jti, so a subsequent legitimate revocation at A hits ON CONFLICT
// DO NOTHING and the token stays valid at A. Post-fix, B refuses the
// foreign token without any durable write and A's revocation works.
func TestCrossRouteRevokePoisonsRouteA(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	store := NewSQLStore(db)
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	const (
		tenant  = "tenant-test"
		routeA  = "r-a"
		routeB  = "r-b"
		client  = "cli_cross"
		issuerA = "https://relay.test/r/" + routeA + "/oauth"
		issuerB = "https://relay.test/r/" + routeB + "/oauth"
	)
	claims := TokenClaims{
		Issuer:   issuerA,
		Subject:  client,
		Audience: "https://relay.test/r/" + routeA + "/mcp",
		Tenant:   tenant,
		Route:    routeA,
		Expiry:   time.Now().Add(time.Hour).Unix(),
		ID:       "jti-cross-route",
	}
	tok, err := issuer.Mint(claims)
	if err != nil {
		t.Fatal(err)
	}
	sA := NewServer(issuer, store, tenant, routeA, "https://relay.test/r/"+routeA+"/mcp", issuerA)
	sB := NewServer(issuer, store, tenant, routeB, "https://relay.test/r/"+routeB+"/mcp", issuerB)

	revoke := func(s *Server, token string) *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set("token", token)
		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		s.ServeRevoke(rec, req)
		return rec
	}
	// Route B's endpoint sees a foreign token: RFC 7009-compatible success,
	// and no durable revocation state anywhere.
	if rec := revoke(sB, tok); rec.Code != http.StatusOK {
		t.Fatalf("cross-route revoke at B status=%d, want 200", rec.Code)
	}
	if revoked, err := store.IsTokenRevoked(claims.ID, tenant, routeB); err != nil || revoked {
		t.Fatalf("route B recorded the foreign token: revoked=%v err=%v", revoked, err)
	}
	// Route A's legitimate revocation still works: the jti is not poisoned.
	if rec := revoke(sA, tok); rec.Code != http.StatusOK {
		t.Fatalf("legit revoke at A status=%d", rec.Code)
	}
	if revoked, err := store.IsTokenRevoked(claims.ID, tenant, routeA); err != nil || !revoked {
		t.Fatalf("legit route-A revocation did not land: revoked=%v err=%v (pre-fix this is the poisoning proof)", revoked, err)
	}
	// Admission refuses the now-revoked token.
	authz := NewAuthorizer(issuer, store)
	rq := httptest.NewRequest(http.MethodPost, "https://relay.test/r/"+routeA+"/mcp", nil)
	rq.Header.Set("Authorization", "Bearer "+tok)
	if err := authz.Authorize(rq, "https://relay.test/r/"+routeA+"/mcp", issuerA, tenant, routeA); err == nil {
		t.Fatal("token accepted after legitimate revocation at route A")
	}
}

// TestCrossRouteRevokeMemStoreNoPoison (review P1 #1, store contract
// parity): the MemStore's revocation key is (jti, tenant, route), so a
// route-scoped insert never affects another route. This pins the contract
// the SQL store must honor.
func TestCrossRouteRevokeMemStoreNoPoison(t *testing.T) {
	m := NewMemStore()
	if err := m.RevokeToken("jti-x", "cli", "t", "route-b"); err != nil {
		t.Fatal(err)
	}
	if revoked, err := m.IsTokenRevoked("jti-x", "t", "route-a"); err != nil || revoked {
		t.Fatalf("store-level cross-route leak: revoked=%v err=%v", revoked, err)
	}
	if revoked, err := m.IsTokenRevoked("jti-x", "t", "route-b"); err != nil || !revoked {
		t.Fatalf("route-b revocation missing: revoked=%v err=%v", revoked, err)
	}
}
