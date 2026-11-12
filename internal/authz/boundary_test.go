package authz

// Boundary regressions for the 2026-11-11 managed-auth rereview. Each test
// names the finding it closes; they fail against the pre-fix tree.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// pkceTestVerifier is a conforming RFC 7636 verifier: 43 unreserved
// characters. Tests must never rely on the old one-character verifiers.
const pkceTestVerifier = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

// completeConsent drives one full authorization transaction against the
// server and returns the redirect Location.
func completeConsent(t *testing.T, s *Server, clientID, pairing, redirectURI, state string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", CodeChallengeS256(pkceTestVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", s.RouteURL)
	q.Set("state", state)
	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authorize status=%d, want 200 consent page", w.Code)
	}
	challenge := extractChallenge(t, w.Body.String())
	form := url.Values{}
	form.Set("challenge", challenge)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_challenge", CodeChallengeS256(pkceTestVerifier))
	form.Set("code_challenge_method", "S256")
	form.Set("resource", s.RouteURL)
	form.Set("state", state)
	form.Set("pairing_secret", pairing)
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeConsent(w2, req2)
	return w2
}

// P1 (pairing lifecycle): the credential is single-use. A second consent
// transaction — even with a FRESH challenge — is refused once the
// credential has authorized one.
func TestPairingSecretSingleUse(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-single-use"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrantWithPairingSecret(clientID, "tenant-test", "r-test", "pair-1", time.Hour); err != nil {
		t.Fatal(err)
	}
	w := completeConsent(t, s, clientID, "pair-1", "http://127.0.0.1:59999/cb", "s1")
	if w.Code != http.StatusFound {
		t.Fatalf("first consent status=%d body=%q, want 302", w.Code, w.Body.String())
	}
	// A fresh authorization with the SAME credential: the credential was
	// burned by the first transaction.
	w2 := completeConsent(t, s, clientID, "pair-1", "http://127.0.0.1:59999/cb", "s2")
	if w2.Code == http.StatusFound {
		t.Fatal("a consumed pairing credential authorized a second transaction")
	}
}

// P1 (pairing lifecycle): the credential expires. An unused credential
// dies at its expiry and consent fails closed.
func TestPairingSecretExpires(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-expiring"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrantWithPairingSecret(clientID, "tenant-test", "r-test", "pair-exp", 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	w := completeConsent(t, s, clientID, "pair-exp", "http://127.0.0.1:59999/cb", "s1")
	if w.Code == http.StatusFound {
		t.Fatal("an expired pairing credential completed a consent")
	}
}

// P1 (ServeConsent binding): every field of the transaction must match the
// stored challenge. Tampering with any one of them is a transaction
// mismatch, not a completed consent.
func TestConsentTransactionBinding(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-binding"
	redirect := "http://127.0.0.1:59999/cb"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{redirect}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrantWithPairingSecret(clientID, "tenant-test", "r-test", "pair-bind", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Mint a challenge through authorize.
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("response_type", "code")
	q.Set("code_challenge", CodeChallengeS256(pkceTestVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", s.RouteURL)
	q.Set("state", "good")
	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", w.Code)
	}
	challenge := extractChallenge(t, w.Body.String())

	post := func(mutate func(url.Values)) int {
		form := url.Values{}
		form.Set("challenge", challenge)
		form.Set("client_id", clientID)
		form.Set("redirect_uri", redirect)
		form.Set("code_challenge", CodeChallengeS256(pkceTestVerifier))
		form.Set("code_challenge_method", "S256")
		form.Set("resource", s.RouteURL)
		form.Set("state", "good")
		form.Set("pairing_secret", "pair-bind")
		mutate(form)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.ServeConsent(rec, req)
		return rec.Code
	}
	// The untampered transaction completes.
	if code := post(func(url.Values) {}); code != http.StatusFound {
		t.Fatalf("clean consent status=%d, want 302", code)
	}
	// Each tampered field is refused.
	cases := map[string]func(url.Values){
		"client_id":    func(v url.Values) { v.Set("client_id", "someone-else") },
		"redirect_uri": func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:59999/other") },
		"challenge_pkce": func(v url.Values) {
			v.Set("code_challenge", CodeChallengeS256("another-verifier-0123456789abcdefghijklmn"))
		},
		"state":    func(v url.Values) { v.Set("state", "swapped") },
		"resource": func(v url.Values) { v.Set("resource", "https://relay.test/r/other/mcp") },
	}
	for name, mutate := range cases {
		if code := post(mutate); code == http.StatusFound {
			t.Fatalf("tampered %s completed a consent", name)
		}
	}
}

// P1 (issueCode): the authorization response parameters are added through
// url.Values, so a redirect URI that already carries query parameters keeps
// them, and the RFC 9207 issuer identifier is present.
func TestRedirectCompositionPreservesQuery(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-query"
	redirect := "http://127.0.0.1:59999/cb?foo=bar&baz=qux"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{redirect}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrantWithPairingSecret(clientID, "tenant-test", "r-test", "pair-q", time.Hour); err != nil {
		t.Fatal(err)
	}
	w := completeConsent(t, s, clientID, "pair-q", redirect, "st")
	if w.Code != http.StatusFound {
		t.Fatalf("consent status=%d", w.Code)
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("redirect unparseable: %v", err)
	}
	got := u.Query()
	for k, want := range map[string]string{"foo": "bar", "baz": "qux", "code": "", "state": "st", "iss": s.IssuerURL} {
		if want == "" {
			if got.Get(k) == "" {
				t.Fatalf("redirect %q missing %q", loc, k)
			}
			continue
		}
		if got.Get(k) != want {
			t.Fatalf("redirect %q: %s=%q, want %q", loc, k, got.Get(k), want)
		}
	}
}

// P1 (PKCE): RFC 7636 verifier and S256 challenge grammar are enforced, so
// a trivially short verifier is rejected instead of hashed into a weak
// comparison.
func TestPKCEGrammarEnforced(t *testing.T) {
	good := CodeChallengeS256(pkceTestVerifier)
	if err := VerifyPKCE("S256", good, pkceTestVerifier); err != nil {
		t.Fatalf("conforming PKCE rejected: %v", err)
	}
	bad := []struct {
		name, method, challenge, verifier string
	}{
		{"short verifier", "S256", good, "v"},
		{"empty verifier", "S256", good, ""},
		{"long verifier", "S256", good, strings.Repeat("a", 129)},
		{"invalid char", "S256", good, "0123456789abcdefghijklmnopqrstuvwxyzABC+EFG"},
		{"wrong method", "plain", good, pkceTestVerifier},
		{"short challenge", "S256", "only-43-chars-is-not-magic-aaaaaaaaaaaaaaaaaaaa", pkceTestVerifier},
		{"non-base64 challenge", "S256", strings.Repeat("!", 43), pkceTestVerifier},
	}
	for _, c := range bad {
		if err := VerifyPKCE(c.method, c.challenge, c.verifier); err == nil {
			t.Fatalf("%s accepted", c.name)
		}
	}
}

// P1 (registration bound): public DCR stops at the per-route quota.
func TestRegistrationQuota(t *testing.T) {
	s, _, _ := newTestServer(t)
	for i := 0; i < MaxClientsPerRoute; i++ {
		body := `{"client_name":"q","redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none"}`
		w := httptest.NewRecorder()
		s.ServeRegister(w, httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
		if w.Code != http.StatusCreated {
			t.Fatalf("registration %d status=%d, want 201", i, w.Code)
		}
	}
	body := `{"client_name":"q","redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none"}`
	w := httptest.NewRecorder()
	s.ServeRegister(w, httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-quota registration status=%d, want 429", w.Code)
	}
}

// P1 (pending-consent bound): starting flows without completing them stops
// at the per-route cap.
func TestPendingConsentQuota(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "client-flood"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxPendingConsentsPerRoute; i++ {
		q := url.Values{}
		q.Set("client_id", clientID)
		q.Set("redirect_uri", "http://127.0.0.1:59999/cb")
		q.Set("response_type", "code")
		q.Set("code_challenge", CodeChallengeS256(pkceTestVerifier))
		q.Set("code_challenge_method", "S256")
		q.Set("resource", s.RouteURL)
		w := httptest.NewRecorder()
		s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
		if w.Code != http.StatusOK {
			t.Fatalf("authorize %d status=%d, want 200", i, w.Code)
		}
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	q.Set("response_type", "code")
	q.Set("code_challenge", CodeChallengeS256(pkceTestVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", s.RouteURL)
	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-quota authorize status=%d, want 429", w.Code)
	}
}

// P1 (approval atomicity): a revoked grant is never resurrected by
// approval, and the combined approve+credential step refuses it too.
func TestApproveRefusesRevokedGrant(t *testing.T) {
	m := NewMemStore()
	if err := m.RegisterClient(Client{ID: "cli_r", Tenant: "t", Route: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateGrant(Grant{ClientID: "cli_r", Tenant: "t", Route: "r", Status: GrantPending}); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeGrant("cli_r", "t", "r"); err != nil {
		t.Fatal(err)
	}
	if err := m.ApproveGrant("cli_r", "t", "r"); err == nil {
		t.Fatal("ApproveGrant resurrected a revoked grant")
	}
	if err := m.ApproveGrantWithPairingSecret("cli_r", "t", "r", "pair", time.Hour); err == nil {
		t.Fatal("ApproveGrantWithPairingSecret resurrected a revoked grant")
	}
}

// P1 (lifecycle pruning): expired codes and challenges and long-retired
// revocations are pruned; live state is untouched.
func TestPruneAuthzExpired(t *testing.T) {
	m := NewMemStore()
	if err := m.CreateCode(Code{Code: "old", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateCode(Code{Code: "live", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateConsent(Consent{Challenge: "oldc", Tenant: "t", Route: "r", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateConsent(Consent{Challenge: "livec", Tenant: "t", Route: "r", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeToken("jti-old", "c", "t", "r"); err != nil {
		t.Fatal(err)
	}
	// Force the old revocation past retention.
	m.mu.Lock()
	m.revocations["jti-old\x00t\x00r"] = time.Now().Add(-DefaultRevocationRetention - time.Hour)
	m.revocations["jti-live\x00t\x00r"] = time.Now()
	m.mu.Unlock()
	if err := m.PruneAuthzExpired(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ConsumeCode("old"); err == nil {
		t.Fatal("expired code survived pruning")
	}
	if _, err := m.ConsumeCode("live"); err != nil {
		t.Fatalf("live code pruned: %v", err)
	}
	if _, err := m.ConsumeConsent("oldc"); err == nil {
		t.Fatal("expired challenge survived pruning")
	}
	if _, err := m.ConsumeConsent("livec"); err != nil {
		t.Fatalf("live challenge pruned: %v", err)
	}
	if revoked, _ := m.IsTokenRevoked("jti-old", "t", "r"); revoked {
		t.Fatal("retention-expired revocation survived pruning")
	}
	if revoked, _ := m.IsTokenRevoked("jti-live", "t", "r"); !revoked {
		t.Fatal("live revocation was pruned")
	}
}

// P1 (pairing consumption is atomic on the durable store): the burn is a
// transaction, so a replay cannot race it.
func TestSQLConsumePairingSecretAtomic(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)
	if err := s.RegisterClient(Client{ID: "cli_p", Tenant: "t", Route: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveGrantWithPairingSecret("cli_p", "t", "r", "pair-sql", time.Hour); err != nil {
		t.Fatal(err)
	}
	ok, err := s.ConsumePairingSecret("cli_p", "t", "r", "pair-sql")
	if err != nil || !ok {
		t.Fatalf("first consume ok=%v err=%v, want true", ok, err)
	}
	ok, err = s.ConsumePairingSecret("cli_p", "t", "r", "pair-sql")
	if err != nil || ok {
		t.Fatalf("replay ok=%v err=%v, want false", ok, err)
	}
	ok, err = s.ConsumePairingSecret("cli_p", "t", "r", "wrong")
	if err != nil || ok {
		t.Fatalf("wrong secret ok=%v err=%v, want false", ok, err)
	}
	// Rotation restores usability with the fresh credential.
	if err := s.SetPairingSecret("cli_p", "t", "r", "pair-sql2", time.Hour); err != nil {
		t.Fatal(err)
	}
	ok, err = s.ConsumePairingSecret("cli_p", "t", "r", "pair-sql2")
	if err != nil || !ok {
		t.Fatalf("rotated credential ok=%v err=%v, want true", ok, err)
	}
	// Expiry fails closed.
	if err := s.SetPairingSecret("cli_p", "t", "r", "pair-sql3", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	ok, err = s.ConsumePairingSecret("cli_p", "t", "r", "pair-sql3")
	if err != nil || ok {
		t.Fatalf("expired credential ok=%v err=%v, want false", ok, err)
	}
}

// P1 (transactional approval): approval and credential issuance land
// together; the grant carries the credential immediately.
func TestApproveWithPairingSecretIsAtomic(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)
	if err := s.ApproveGrantWithPairingSecret("cli_a", "t", "r", "pair-a", time.Hour); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetGrant("cli_a", "t", "r")
	if err != nil || g.Status != GrantActive {
		t.Fatalf("grant=%+v err=%v", g, err)
	}
	if g.PairingHash == "" || g.PairingExpiresAt.IsZero() || g.PairingConsumedAt != nil {
		t.Fatalf("credential not persisted atomically: %+v", g)
	}
	if g.PairingHash != HashSecret("pair-a") {
		t.Fatal("stored credential is not the hash of the issued secret")
	}
}
