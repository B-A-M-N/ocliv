package authz

// Failing-first regressions for the 2026-11-14 review's client-ownership
// and code-redemption boundary findings (P1 #2 and #3).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// pkceVerifier is a conforming RFC 7636 verifier (43 unreserved chars).
const pkceVerifier = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

// registerRouteClient registers a client through a specific route-scoped
// server and returns the minted client id.
func registerRouteClient(t *testing.T, s *Server, redirect string) string {
	t.Helper()
	body := `{"client_name":"scope","redirect_uris":["` + redirect + `"],"token_endpoint_auth_method":"none"}`
	w := httptest.NewRecorder()
	s.ServeRegister(w, httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("register: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp["client_id"].(string)
}

// TestClientRegistrationRouteOwnership (review P1 #2): GetClient must
// return the tenant/route the client was registered through, and the
// authorization handlers must refuse a cross-route client.
func TestClientRegistrationRouteOwnership(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	store := NewSQLStore(db)
	if err := store.RegisterClient(Client{ID: "cli-owned", Name: "c",
		RedirectURIs: []string{"https://client.example/cb"}, CreatedAt: time.Now(),
		Tenant: "tenant-a", Route: "route-a"}); err != nil {
		t.Fatal(err)
	}
	c, err := store.GetClient("cli-owned")
	if err != nil {
		t.Fatal(err)
	}
	if c.Tenant != "tenant-a" || c.Route != "route-a" {
		t.Fatalf("GetClient lost ownership: tenant=%q route=%q, want tenant-a/route-a (review P1 #2)", c.Tenant, c.Route)
	}
}

// TestCrossRouteAuthorizeRefused (review P1 #2, handler level): a client
// registered through route A cannot start an authorization on route B.
// Both shared-tenant (tenant-a/route-b) and cross-tenant destinations
// must fail without creating an active grant or a code.
func TestCrossRouteAuthorizeRefused(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	sA := NewServer(issuer, store, "tenant-a", "route-a", "https://relay.test/r/route-a/mcp", "https://relay.test/r/route-a/oauth")
	sB := NewServer(issuer, store, "tenant-a", "route-b", "https://relay.test/r/route-b/mcp", "https://relay.test/r/route-b/oauth")

	client := registerRouteClient(t, sA, "https://client.example/cb")
	// Approve the client on route A only.
	if err := store.ApproveGrantWithPairingSecret(client, "tenant-a", "route-a", "pair-a", time.Hour); err != nil {
		t.Fatal(err)
	}

	attempt := func(s *Server) *httptest.ResponseRecorder {
		q := url.Values{}
		q.Set("client_id", client)
		q.Set("redirect_uri", "https://client.example/cb")
		q.Set("response_type", "code")
		q.Set("code_challenge", CodeChallengeS256(pkceVerifier))
		q.Set("code_challenge_method", "S256")
		q.Set("resource", s.RouteURL)
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		s.ServeAuthorize(rec, req)
		return rec
	}
	// Same tenant, different route: refused (pre-fix, this renders B's
	// consent page because the client's identity is global).
	if rec := attempt(sB); rec.Code == http.StatusOK {
		t.Fatalf("route B accepted a route-A client: body=%s (review P1 #2)", rec.Body.String())
	}
	// Cross-tenant destination with a distinct route.
	sC := NewServer(issuer, store, "tenant-b", "route-b", "https://relay.test/r/route-b/mcp", "https://relay.test/r/route-b/oauth")
	if rec := attempt(sC); rec.Code == http.StatusOK {
		t.Fatalf("tenant-b/route-b accepted a tenant-a/route-a client")
	}
	// No durable grant may have been created on route B.
	if g, err := store.GetGrant(client, "tenant-a", "route-b"); err == nil && g.Status == GrantActive {
		t.Fatal("cross-route authorize created an active grant on route B")
	}
	if g, err := store.GetGrant(client, "tenant-b", "route-b"); err == nil && g.Status == GrantActive {
		t.Fatal("cross-tenant authorize created an active grant on route B")
	}
	// Route A's own authorization still works end to end.
	if rec := attempt(sA); rec.Code != http.StatusOK {
		t.Fatalf("route A authorize broken by the boundary check: %d %s", rec.Code, rec.Body.String())
	}
}

// TestCrossRouteConsentRefused (review P1 #2 #4): the consent completion
// and pairing-credential consumption are route-scoped too. A challenge
// and credential minted on route A cannot be completed on route B.
func TestCrossRouteConsentRefused(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	sA := NewServer(issuer, store, "tenant-a", "route-a", "https://relay.test/r/route-a/mcp", "https://relay.test/r/route-a/oauth")
	sB := NewServer(issuer, store, "tenant-a", "route-b", "https://relay.test/r/route-b/mcp", "https://relay.test/r/route-b/oauth")
	client := registerRouteClient(t, sA, "https://client.example/cb")
	if err := store.ApproveGrantWithPairingSecret(client, "tenant-a", "route-a", "pair-a", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Start the flow on A to mint a challenge bound to route A.
	q := url.Values{}
	q.Set("client_id", client)
	q.Set("redirect_uri", "https://client.example/cb")
	q.Set("response_type", "code")
	q.Set("code_challenge", CodeChallengeS256(pkceVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", sA.RouteURL)
	w := httptest.NewRecorder()
	sA.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	challenge := extractChallenge(t, w.Body.String())

	// Complete it on route B: the challenge is route-A bound, so B must
	// refuse it before consuming the pairing credential.
	form := url.Values{}
	form.Set("challenge", challenge)
	form.Set("client_id", client)
	form.Set("redirect_uri", "https://client.example/cb")
	form.Set("code_challenge", CodeChallengeS256(pkceVerifier))
	form.Set("code_challenge_method", "S256")
	form.Set("resource", sB.RouteURL)
	form.Set("pairing_secret", "pair-a")
	wB := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sB.ServeConsent(wB, req)
	if wB.Code == http.StatusFound {
		t.Fatal("route B completed route A's consent challenge")
	}
	// The credential is NOT burned: the mismatch was refused before
	// any credential consumption.
	ok, err := store.ConsumePairingSecret(client, "tenant-a", "route-a", "pair-a")
	if err != nil || !ok {
		t.Fatalf("route B burned route A's pairing credential: ok=%v err=%v", ok, err)
	}
}

// TestCrossRouteCodeRedemptionRefused (review P1 #3): a code minted on
// route A cannot be redeemed at route B, even when the same client id
// holds an ACTIVE grant on route B. The attempt must NOT consume A's
// code.
func TestCrossRouteCodeRedemptionRefused(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	sA := NewServer(issuer, store, "tenant-a", "route-a", "https://relay.test/r/route-a/mcp", "https://relay.test/r/route-a/oauth")
	sB := NewServer(issuer, store, "tenant-a", "route-b", "https://relay.test/r/route-b/mcp", "https://relay.test/r/route-b/oauth")
	client := registerRouteClient(t, sA, "https://client.example/cb")
	// The same client holds active grants on BOTH routes.
	if err := store.ApproveGrant(client, "tenant-a", "route-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrant(client, "tenant-a", "route-b"); err != nil {
		t.Fatal(err)
	}
	codeStr := "cross-code"
	if err := store.CreateCode(Code{Code: codeStr, ClientID: client, Tenant: "tenant-a",
		Route: "route-a", RedirectURI: "https://client.example/cb",
		Challenge: CodeChallengeS256(pkceVerifier), ChallengeMethod: "S256",
		Scope: "mcp:tools offline_access", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// Redeem at B: pre-fix, this consumes A's code and mints B tokens.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", codeStr)
	form.Set("client_id", client)
	form.Set("redirect_uri", "https://client.example/cb")
	form.Set("code_verifier", pkceVerifier)
	form.Set("resource", sB.RouteURL)
	wB := httptest.NewRecorder()
	reqB := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	reqB.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sB.ServeToken(wB, reqB)
	if wB.Code == http.StatusOK {
		t.Fatalf("route B redeemed route A's code: %s (review P1 #3)", wB.Body.String())
	}
	// The code is untouched: a legitimate redemption at A still works.
	formA := url.Values{}
	formA.Set("grant_type", "authorization_code")
	formA.Set("code", codeStr)
	formA.Set("client_id", client)
	formA.Set("redirect_uri", "https://client.example/cb")
	formA.Set("code_verifier", pkceVerifier)
	formA.Set("resource", sA.RouteURL)
	wA := httptest.NewRecorder()
	reqA := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formA.Encode()))
	reqA.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sA.ServeToken(wA, reqA)
	if wA.Code != http.StatusOK {
		t.Fatalf("route A's code destroyed by route B's attempt: %d %s", wA.Code, wA.Body.String())
	}
	// The code is now consumed and a replay fails.
	wA2 := httptest.NewRecorder()
	reqA2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formA.Encode()))
	reqA2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sA.ServeToken(wA2, reqA2)
	if wA2.Code == http.StatusOK {
		t.Fatal("authorization code replayed after legitimate redemption")
	}
}

// TestCrossTenantCodeRedemptionRefused (review P1 #3): the same code-scope
// fence applies across tenants.
func TestCrossTenantCodeRedemptionRefused(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	sA := NewServer(issuer, store, "tenant-a", "route-a", "https://relay.test/r/route-a/mcp", "https://relay.test/r/route-a/oauth")
	sB := NewServer(issuer, store, "tenant-b", "route-a", "https://relay.test/r/route-a/mcp", "https://relay.test/r/route-a/oauth")
	client := registerRouteClient(t, sA, "https://client.example/cb")
	if err := store.ApproveGrant(client, "tenant-a", "route-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrant(client, "tenant-b", "route-a"); err != nil {
		t.Fatal(err)
	}
	codeStr := "cross-tenant-code"
	if err := store.CreateCode(Code{Code: codeStr, ClientID: client, Tenant: "tenant-a",
		Route: "route-a", RedirectURI: "https://client.example/cb",
		Challenge: CodeChallengeS256(pkceVerifier), ChallengeMethod: "S256",
		Scope: "mcp:tools offline_access", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", codeStr)
	form.Set("client_id", client)
	form.Set("redirect_uri", "https://client.example/cb")
	form.Set("code_verifier", pkceVerifier)
	form.Set("resource", sB.RouteURL)
	wB := httptest.NewRecorder()
	reqB := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	reqB.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sB.ServeToken(wB, reqB)
	if wB.Code == http.StatusOK {
		t.Fatal("tenant-b redeemed tenant-a's code")
	}
	// Tenant A's code still redeems.
	formA := url.Values{}
	formA.Set("grant_type", "authorization_code")
	formA.Set("code", codeStr)
	formA.Set("client_id", client)
	formA.Set("redirect_uri", "https://client.example/cb")
	formA.Set("code_verifier", pkceVerifier)
	formA.Set("resource", sA.RouteURL)
	wA := httptest.NewRecorder()
	reqA := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formA.Encode()))
	reqA.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sA.ServeToken(wA, reqA)
	if wA.Code != http.StatusOK {
		t.Fatalf("tenant-a's code destroyed by tenant-b's attempt: %d %s", wA.Code, wA.Body.String())
	}
}

// TestConcurrentCodeRedemptionSingleWinner (review P1 #3): one code is
// exactly single-use even under concurrency, and a mismatched redemption
// does not consume it.
func TestConcurrentCodeRedemptionSingleWinner(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	sA := NewServer(issuer, store, "tenant-a", "route-a", "https://relay.test/r/route-a/mcp", "https://relay.test/r/route-a/oauth")
	client := registerRouteClient(t, sA, "https://client.example/cb")
	if err := store.ApproveGrant(client, "tenant-a", "route-a"); err != nil {
		t.Fatal(err)
	}
	codeStr := "race-code"
	if err := store.CreateCode(Code{Code: codeStr, ClientID: client, Tenant: "tenant-a",
		Route: "route-a", RedirectURI: "https://client.example/cb",
		Challenge: CodeChallengeS256(pkceVerifier), ChallengeMethod: "S256",
		Scope: "mcp:tools offline_access", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	grant := func() int {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", codeStr)
		form.Set("client_id", client)
		form.Set("redirect_uri", "https://client.example/cb")
		form.Set("code_verifier", pkceVerifier)
		form.Set("resource", sA.RouteURL)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		sA.ServeToken(w, req)
		return w.Code
	}
	const racers = 8
	var wg sync.WaitGroup
	results := make([]int, racers)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = grant()
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, c := range results {
		if c == http.StatusOK {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent code redemption produced %d winners, want exactly 1", wins)
	}
}

// TestLegacyUnboundClientFailsClosed (review P1 #2 #5): a client row with
// no tenant/route identity (pre-V11 or a corrupted row) is not admitted to
// any route.
func TestLegacyUnboundClientFailsClosed(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	if err := store.RegisterClient(Client{ID: "cli-legacy", Name: "c",
		RedirectURIs: []string{"https://client.example/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s := NewServer(issuer, store, "tenant-a", "route-a", "https://relay.test/r/route-a/mcp", "https://relay.test/r/route-a/oauth")
	q := url.Values{}
	q.Set("client_id", "cli-legacy")
	q.Set("redirect_uri", "https://client.example/cb")
	q.Set("response_type", "code")
	q.Set("code_challenge", CodeChallengeS256(pkceVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", s.RouteURL)
	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if w.Code == http.StatusOK {
		t.Fatalf("legacy unbound client admitted to route A: body=%s", w.Body.String())
	}
}
