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

func newTestServer(t *testing.T) (*Server, *Issuer, *MemStore) {
	t.Helper()
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	store := NewMemStore()
	s := NewServer(issuer, store, "tenant-test", "r-test", "https://relay.test/r/r-test/mcp", "https://relay.test")
	s.CodeTTL = 5 * time.Minute
	s.TokenTTL = 1 * time.Hour
	return s, issuer, store
}

// register creates a client with one redirect URI.
func register(t *testing.T, s *Server, redirect string) string {
	t.Helper()
	body := `{"client_name":"test client","redirect_uris":["` + redirect + `"],"token_endpoint_auth_method":"none"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	s.ServeRegister(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("register decode: %v", err)
	}
	id, _ := resp["client_id"].(string)
	if id == "" {
		t.Fatal("register: no client_id")
	}
	return id
}

func TestMintVerifyRoundTrip(t *testing.T) {
	s, issuer, _ := newTestServer(t)
	tok, err := issuer.Mint(TokenClaims{
		Issuer:   s.IssuerURL,
		Subject:  "cli_a",
		Audience: s.RouteURL,
		Tenant:   "tenant-default",
		Route:    s.RouteID,
		Expiry:   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := issuer.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Issuer != s.IssuerURL {
		t.Fatalf("iss=%q", claims.Issuer)
	}
	if claims.Subject != "cli_a" {
		t.Fatalf("sub=%q", claims.Subject)
	}
	if !claims.ValidateAudience(s.RouteURL) {
		t.Fatalf("aud=%v", claims.Audience)
	}
	if claims.Tenant != "tenant-default" || claims.Route != s.RouteID {
		t.Fatalf("tenant/route claims wrong: %+v", claims)
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	s, issuer, _ := newTestServer(t)
	tok, err := issuer.Mint(TokenClaims{
		Issuer: s.IssuerURL, Subject: "cli_a", Audience: s.RouteURL,
		Tenant: "tenant-default", Route: s.RouteID, Expiry: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token shape: %d parts", len(parts))
	}
	tampered := parts[0] + "." + parts[1] + ".AAAA"
	if _, err := issuer.Verify(tampered); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestVerifyRejectsWrongIssuerAndAudience(t *testing.T) {
	s, issuer, _ := newTestServer(t)
	tok, err := issuer.Mint(TokenClaims{
		Issuer: "https://evil.test", Subject: "cli_a", Audience: s.RouteURL,
		Tenant: "tenant-default", Route: s.RouteID, Expiry: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := issuer.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.ValidateIssuer(s.IssuerURL) {
		t.Fatal("wrong issuer accepted")
	}

	tok2, err := issuer.Mint(TokenClaims{
		Issuer: s.IssuerURL, Subject: "cli_a", Audience: "https://other.test/r/x/mcp",
		Tenant: "tenant-default", Route: s.RouteID, Expiry: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint2: %v", err)
	}
	claims2, err := issuer.Verify(tok2)
	if err != nil {
		t.Fatalf("verify2: %v", err)
	}
	if claims2.ValidateAudience(s.RouteURL) {
		t.Fatal("wrong audience accepted")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	s, issuer, _ := newTestServer(t)
	tok, err := issuer.Mint(TokenClaims{
		Issuer: s.IssuerURL, Subject: "cli_a", Audience: s.RouteURL,
		Tenant: "tenant-default", Route: s.RouteID, Expiry: time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := issuer.Verify(tok); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestIssuerKeyRoundTrip(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	restored, err := IssuerFromKey(issuer.KID(), issuer.PrivateKeyBytes())
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	tok, err := issuer.Mint(TokenClaims{
		Issuer: "iss", Subject: "sub", Audience: "aud", Expiry: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := restored.Verify(tok); err != nil {
		t.Fatalf("restored issuer cannot verify: %v", err)
	}
	if len(restored.JWKS()) != 1 || restored.JWKS()[0].Kid != issuer.KID() {
		t.Fatalf("jwks mismatch: %+v", restored.JWKS())
	}
}

func TestJWKSIsEd25519(t *testing.T) {
	s, _, _ := newTestServer(t)
	body, err := s.Issuer.JWKSJSON()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys=%d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" || k.X == "" {
		t.Fatalf("jwk shape wrong: %+v", k)
	}
}

func TestPKCEOnlyS256(t *testing.T) {
	verifier := "a" + strings.Repeat("b", 60)
	challenge := CodeChallengeS256(verifier)
	if err := VerifyPKCE("S256", challenge, verifier); err != nil {
		t.Fatalf("valid S256 rejected: %v", err)
	}
	if err := VerifyPKCE("S256", challenge, "wrong"); err == nil {
		t.Fatal("wrong verifier accepted")
	}
	if err := VerifyPKCE("plain", verifier, verifier); err == nil {
		t.Fatal("plain PKCE accepted")
	}
	if err := VerifyPKCE("S256", challenge, ""); err == nil {
		t.Fatal("missing verifier accepted")
	}
}

func TestValidateRedirectURI(t *testing.T) {
	allow := []string{"https://client.example/callback"}
	ok := []string{"https://client.example/callback"}
	for _, u := range ok {
		if err := ValidateRedirectURI(u, allow); err != nil {
			t.Fatalf("valid uri rejected: %s: %v", u, err)
		}
	}
	bad := []string{
		"http://client.example/callback",       // non-loopback http
		"https://127.0.0.1/callback",           // not in allowlist
		"https://client.example/other",         // not in allowlist
		"https://client.example/callback#frag", // fragment
		"https://user@client.example/callback", // userinfo
		"",                                     // empty
		"ftp://client.example/callback",        // bad scheme
	}
	for _, u := range bad {
		if err := ValidateRedirectURI(u, allow); err == nil {
			t.Fatalf("invalid uri accepted: %q", u)
		}
	}
	// Loopback http is allowed for native clients.
	if err := ValidateRedirectURI("http://127.0.0.1:8080/cb", []string{"http://127.0.0.1:8080/cb"}); err != nil {
		t.Fatalf("loopback native redirect rejected: %v", err)
	}
}

func TestIsPrivateHost(t *testing.T) {
	private := []string{"127.0.0.1", "localhost", "::1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "172.16.0.1", "172.31.255.255", "fd00::1", "fe80::1"}
	for _, h := range private {
		if !IsPrivateHost(h) {
			t.Fatalf("expected private: %s", h)
		}
	}
	public := []string{"8.8.8.8", "172.32.0.1", "example.com", "1.1.1.1"}
	for _, h := range public {
		if IsPrivateHost(h) {
			t.Fatalf("expected public: %s", h)
		}
	}
}

func TestStoreGrantLifecycle(t *testing.T) {
	m := NewMemStore()
	if err := m.RegisterClient(Client{ID: "cli_1", RedirectURIs: []string{"https://x/cb"}}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := m.RegisterClient(Client{ID: "cli_1"}); err == nil {
		t.Fatal("duplicate client accepted")
	}
	if err := m.CreateGrant(Grant{ClientID: "cli_1", Tenant: "t", Route: "r", Status: GrantPending}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := m.CreateGrant(Grant{ClientID: "cli_1", Tenant: "t", Route: "r", Status: GrantPending}); err == nil {
		t.Fatal("duplicate grant accepted")
	}
	if err := m.ApproveGrant("cli_1", "t", "r"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	g, _ := m.GetGrant("cli_1", "t", "r")
	if g.Status != GrantActive {
		t.Fatalf("status=%q", g.Status)
	}
	if err := m.RevokeGrant("cli_1", "t", "r"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	g, _ = m.GetGrant("cli_1", "t", "r")
	if g.Status != GrantRevoked {
		t.Fatalf("status=%q", g.Status)
	}
}

func TestCodeSingleUse(t *testing.T) {
	m := NewMemStore()
	if err := m.CreateCode(Code{Code: "c1", ClientID: "cli_1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := m.ConsumeCode("c1"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := m.ConsumeCode("c1"); err == nil {
		t.Fatal("code replayed")
	}
	if err := m.CreateCode(Code{Code: "c2", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("create2: %v", err)
	}
	if _, err := m.ConsumeCode("c2"); err == nil {
		t.Fatal("expired code accepted")
	}
}

func TestProtectedResourceAndASMetadata(t *testing.T) {
	s, _, _ := newTestServer(t)
	prm := s.ProtectedResourceMetadata()
	if prm["resource"] != s.RouteURL {
		t.Fatalf("prm resource=%v", prm["resource"])
	}
	servers, _ := prm["authorization_servers"].([]string)
	if len(servers) != 1 || servers[0] != s.IssuerURL {
		t.Fatalf("prm authorization_servers=%v", servers)
	}
	as := s.AuthorizationServerMetadata()
	if as["issuer"] != s.IssuerURL {
		t.Fatalf("as issuer=%v", as["issuer"])
	}
	methods, _ := as["code_challenge_methods_supported"].([]string)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("as pkce methods=%v", methods)
	}
	if as["resource_indicators_supported"] != true {
		t.Fatal("resource indicators not advertised")
	}
}

func TestAuthorizePendingThenActive(t *testing.T) {
	s, _, store := newTestServer(t)
	client := register(t, s, "https://client.example/cb")

	// First authorize: pending, so a consent page, not a redirect.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?response_type=code&client_id="+client+
		"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_challenge="+CodeChallengeS256("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")+
		"&code_challenge_method=S256&state=xyz&resource="+url.QueryEscape(s.RouteURL), nil)
	s.ServeAuthorize(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("first authorize: status=%d", w.Code)
	}
	if w.Header().Get("Location") != "" {
		t.Fatal("pending authorize must not redirect")
	}

	// The operator approves and issues the pairing credential; consent is
	// given by POST against the one-time challenge.
	if err := store.ApproveGrantWithPairingSecret(client, s.tenant(), s.RouteID, "pair-secret", time.Hour); err != nil {
		t.Fatalf("pairing secret: %v", err)
	}
	challenge := extractChallenge(t, w.Body.String())
	form := url.Values{}
	form.Set("challenge", challenge)
	form.Set("client_id", client)
	form.Set("redirect_uri", "https://client.example/cb")
	form.Set("code_challenge", CodeChallengeS256("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"))
	form.Set("state", "xyz")
	form.Set("resource", s.RouteURL)
	form.Set("pairing_secret", "pair-secret")
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeConsent(w2, r2)
	if w2.Code != http.StatusFound {
		t.Fatalf("consent: status=%d", w2.Code)
	}
	loc := w2.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://client.example/cb?code=") {
		t.Fatalf("redirect=%q", loc)
	}
}

func TestAuthorizeRequiresPKCE(t *testing.T) {
	s, _, _ := newTestServer(t)
	client := register(t, s, "https://client.example/cb")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?response_type=code&client_id="+client+
		"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb", nil)
	s.ServeAuthorize(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing PKCE: status=%d", w.Code)
	}
}

func TestAuthorizeRejectsWrongResource(t *testing.T) {
	s, _, _ := newTestServer(t)
	client := register(t, s, "https://client.example/cb")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?response_type=code&client_id="+client+
		"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_challenge="+CodeChallengeS256("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")+
		"&code_challenge_method=S256&resource=https%3A%2F%2Fother.test%2Fr%2Fx%2Fmcp", nil)
	s.ServeAuthorize(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong resource: status=%d", w.Code)
	}
}

func TestTokenExchangeAndVerify(t *testing.T) {
	s, issuer, _ := newTestServer(t)
	client := register(t, s, "https://client.example/cb")
	if err := s.Store.CreateGrant(Grant{ClientID: client, Tenant: s.tenant(), Route: s.RouteID, Status: GrantActive}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	verifier := "v" + strings.Repeat("b", 42)
	if err := s.Store.CreateCode(Code{
		Code: "code1", ClientID: client, Tenant: s.tenant(), Route: s.RouteID,
		RedirectURI: "https://client.example/cb", Challenge: CodeChallengeS256(verifier),
		ChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("code: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=code1&client_id="+client+
			"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_verifier="+verifier+
			"&resource="+url.QueryEscape(s.RouteURL)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeToken(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	tok, _ := resp["access_token"].(string)
	if tok == "" {
		t.Fatal("no access token")
	}
	claims, err := issuer.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != client {
		t.Fatalf("sub=%q", claims.Subject)
	}
}

func TestTokenExchangeRejectsBadPKCE(t *testing.T) {
	s, _, _ := newTestServer(t)
	client := register(t, s, "https://client.example/cb")
	if err := s.Store.CreateGrant(Grant{ClientID: client, Tenant: s.tenant(), Route: s.RouteID, Status: GrantActive}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := s.Store.CreateCode(Code{
		Code: "code1", ClientID: client, Tenant: s.tenant(), Route: s.RouteID,
		RedirectURI: "https://client.example/cb", Challenge: CodeChallengeS256("right"),
		ChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("code: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code=code1&client_id="+client+
			"&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_verifier=wrong"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad PKCE accepted: status=%d", w.Code)
	}
}

func TestRegisterRejectsBadRedirect(t *testing.T) {
	s, _, _ := newTestServer(t)
	cases := []string{
		`{"redirect_uris":["http://example.com/cb"]}`,
		`{"redirect_uris":["https://127.0.0.1:9/cb"]}`,
		`{"redirect_uris":["https://10.0.0.5/cb"]}`,
		`{"redirect_uris":["https://client.example/cb#frag"]}`,
		`{"client_name":"x"}`,
	}
	for _, body := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		s.ServeRegister(w, r)
		if w.Code == http.StatusCreated {
			t.Fatalf("bad registration accepted: %s", body)
		}
	}
}
