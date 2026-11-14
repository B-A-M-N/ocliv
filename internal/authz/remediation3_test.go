package authz

// Failing-first regressions for the 2026-11-12 final pre-production pass.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// E: a malformed or empty stored expiry must DENY the credential. The old
// condition (perr == nil && now.After(exp)) silently skipped the expiry
// check when the timestamp did not parse, so corrupted state became an
// eternal credential.
func TestConsumePairingSecretFailsClosedOnBadExpiry(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	s := NewSQLStore(db)
	if err := s.RegisterClient(Client{ID: "cli_e", Tenant: "t", Route: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveGrantWithPairingSecret("cli_e", "t", "r", "pair-e", time.Hour); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, expiry string }{
		{"malformed", "not-a-timestamp"},
		{"empty", ""},
		{"truncated rfc3339", "2026-11-12T19:5"},
		{"expired", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)},
	}
	for _, c := range cases {
		if _, err := db.Exec(`UPDATE authz_grants SET pairing_expires_at=?, pairing_consumed_at=NULL WHERE client_id=?`, c.expiry, "cli_e"); err != nil {
			t.Fatal(err)
		}
		ok, err := s.ConsumePairingSecret("cli_e", "t", "r", "pair-e")
		if err != nil {
			t.Fatalf("%s expiry: unexpected error %v", c.name, err)
		}
		if ok {
			t.Fatalf("%s expiry authorized a credential", c.name)
		}
	}
	// A valid, unexpired, unconsumed credential still works.
	if err := s.SetPairingSecret("cli_e", "t", "r", "pair-e2", time.Hour); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumePairingSecret("cli_e", "t", "r", "pair-e2"); err != nil || !ok {
		t.Fatalf("valid credential ok=%v err=%v, want true", ok, err)
	}
}

// D: redirect URI parsing must handle bracketed IPv6 literals. A native
// client callback such as http://[::1]:59999/cb is a legitimate loopback
// redirect; the old colon-splitting parser reduced the host to "[" and
// rejected it, while misclassifying other IPv6 literals.
func TestValidateRedirectURIIPv6(t *testing.T) {
	ok := []struct{ uri, why string }{
		{"http://[::1]:59999/cb", "loopback IPv6 native callback"},
		{"http://[::1]/cb", "loopback IPv6 without port"},
		{"http://[0:0:0:0:0:0:0:1]/cb", "expanded loopback IPv6"},
		{"http://[::ffff:127.0.0.1]:59999/cb", "IPv4-mapped loopback over http is loopback"},
		{"https://[2001:db8::1]/cb", "documentation IPv6 literal over https"},
		{"https://client.example/cb", "ordinary hostname"},
		{"https://client.example:8443/cb", "hostname with port"},
	}
	for _, c := range ok {
		if err := ValidateRedirectURI(c.uri, []string{c.uri}); err != nil {
			t.Fatalf("%s rejected (%s): %v", c.uri, c.why, err)
		}
	}
	bad := []struct{ uri, why string }{
		{"http://[::1]:59999/cb", ""}, // handled below (allowlist mismatch)
		{"https://[::1]/cb", "loopback IPv6 over https is not a native-client shape"},
		{"https://[fd00::1]/cb", "private IPv6 ULA over https"},
		{"https://[fe80::1]/cb", "link-local IPv6"},
		{"https://[10.0.0.5]/cb", "IPv4 private literal over https"},
		{"http://[fd00::1]/cb", "private IPv6 over http"},
		{"https://[::ffff:127.0.0.1]/cb", "IPv4-mapped loopback over https"},
		{"https://user@client.example/cb", "userinfo"},
		{"https://client.example/cb#frag", "fragment"},
		{"https://client.example/cb", ""}, // handled below (allowlist mismatch)
		{"http://192.168.1.7/cb", "IPv4 private over http"},
		{"ftp://client.example/cb", "scheme"},
		{"", "empty"},
		{"https://[::1", "unterminated IPv6 bracket"},
	}
	for _, c := range bad {
		err := ValidateRedirectURI(c.uri, []string{"https://client.example/cb", "http://127.0.0.1:59999/cb"})
		if err == nil && c.why != "" {
			t.Fatalf("accepted %s (%s)", c.uri, c.why)
		}
	}
	// Exact allowlist matching is preserved for the bracketed form.
	if err := ValidateRedirectURI("http://[::1]:59999/cb", []string{"http://[::1]:59999/other"}); err == nil {
		t.Fatal("an unregistered bracketed callback was accepted")
	}
	if err := ValidateRedirectURI("http://[::1]:59999/cb", []string{"http://[::1]:59999/cb"}); err != nil {
		t.Fatalf("registered bracketed callback rejected: %v", err)
	}
}

// B: public DCR must be bounded ATOMICALLY. The old count-then-insert
// sequence let concurrent registrations cross the quota, so the route's
// durable client table could exceed its bound under load.
func TestRegistrationQuotaIsAtomicUnderConcurrency(t *testing.T) {
	s, _, _ := newTestServer(t)
	const attempts = MaxClientsPerRoute + 25
	var wg sync.WaitGroup
	codes := make([]int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"client_name":"race","redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none"}`
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
			s.ServeRegister(w, r)
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()
	created := 0
	for _, c := range codes {
		if c == http.StatusCreated {
			created++
		}
	}
	n, err := s.Store.CountClients("tenant-test", "r-test")
	if err != nil {
		t.Fatal(err)
	}
	if n != MaxClientsPerRoute || created != MaxClientsPerRoute {
		t.Fatalf("concurrent registration crossed the bound: created=%d stored=%d, want %d/%d",
			created, n, MaxClientsPerRoute, MaxClientsPerRoute)
	}
}

// B: abandoned registrations must be reclaimable so a bounded table cannot
// be permanently exhausted by clients that never obtained approval, while
// approved and revoked identities are never deleted.
func TestAbandonedClientReclamation(t *testing.T) {
	m := NewMemStore()
	now := time.Now()
	reg := func(id string, revoked bool, age time.Duration) Client {
		c := Client{ID: id, Name: id, RedirectURIs: []string{"https://x/cb"},
			CreatedAt: now.Add(-age), Tenant: "t", Route: "r"}
		if revoked {
			t := now.Add(-age / 2)
			c.RevokedAt = &t
		}
		if err := m.RegisterClient(c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	reg("abandoned-old", false, MaxPendingClientAge+time.Hour)
	reg("abandoned-fresh", false, time.Minute)
	reg("revoked-old", true, MaxPendingClientAge+time.Hour)
	reg("approved-old", false, MaxPendingClientAge+time.Hour)
	// An approved client carries a grant row: it must never be reclaimed.
	if err := m.CreateGrant(Grant{ClientID: "approved-old", Tenant: "t", Route: "r",
		Status: GrantActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	// A client whose grant is revoked still carries authorization state.
	reg("grant-revoked-old", false, MaxPendingClientAge+time.Hour)
	if err := m.CreateGrant(Grant{ClientID: "grant-revoked-old", Tenant: "t", Route: "r",
		Status: GrantRevoked, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	n, err := m.PruneAbandonedClients(now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reclaimed %d clients, want exactly 1 (the abandoned, never-approved one)", n)
	}
	for _, id := range []string{"abandoned-fresh", "revoked-old", "approved-old", "grant-revoked-old"} {
		if _, err := m.GetClient(id); err != nil {
			t.Fatalf("client %s was deleted: %v", id, err)
		}
	}
	if _, err := m.GetClient("abandoned-old"); err == nil {
		t.Fatal("abandoned client survived reclamation")
	}
}

// P3: refresh tokens let an approved client keep working without hourly
// operator credentials, while staying revocable and single-use.
func TestRefreshTokenRotation(t *testing.T) {
	s, issuer, store := newTestServer(t)
	clientID := "client-refresh"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now(),
		Tenant: "tenant-test", Route: "r-test"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrantWithPairingSecret(clientID, s.tenant(), s.RouteID, "pair-r", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Complete a consent to reach the code grant.
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	q.Set("response_type", "code")
	q.Set("code_challenge", CodeChallengeS256(pkceTestVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", s.RouteURL)
	q.Set("state", "s")
	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: %d", w.Code)
	}
	challenge := extractChallenge(t, w.Body.String())
	form := url.Values{}
	form.Set("challenge", challenge)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	form.Set("code_challenge", CodeChallengeS256(pkceTestVerifier))
	form.Set("code_challenge_method", "S256")
	form.Set("resource", s.RouteURL)
	form.Set("state", "s")
	form.Set("pairing_secret", "pair-r")
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeConsent(w2, req2)
	if w2.Code != http.StatusFound {
		t.Fatalf("consent: %d body=%q", w2.Code, w2.Body.String())
	}
	code := w2.Header().Get("Location")
	if i := strings.Index(code, "code="); i >= 0 {
		code = code[i+len("code="):]
		if j := strings.Index(code, "&"); j >= 0 {
			code = code[:j]
		}
	}
	// The code grant returns both credentials.
	tform := url.Values{}
	tform.Set("grant_type", "authorization_code")
	tform.Set("code", code)
	tform.Set("client_id", clientID)
	tform.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	tform.Set("code_verifier", pkceTestVerifier)
	tform.Set("resource", s.RouteURL)
	w3 := httptest.NewRecorder()
	treq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tform.Encode()))
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeToken(w3, treq)
	if w3.Code != http.StatusOK {
		t.Fatalf("code grant: %d body=%q", w3.Code, w3.Body.String())
	}
	var pair1 struct {
		Access      string `json:"access_token"`
		Refresh     string `json:"refresh_token"`
		RefreshType string `json:"token_type"`
	}
	_ = json.Unmarshal(w3.Body.Bytes(), &pair1)
	if pair1.Access == "" || pair1.Refresh == "" {
		t.Fatalf("code grant issued no refresh token: %s", w3.Body.String())
	}
	// The refresh token must not admit route access.
	rq := httptest.NewRequest(http.MethodPost, s.RouteURL, nil)
	rq.Header.Set("Authorization", "Bearer "+pair1.Refresh)
	authz := NewAuthorizer(issuer, store)
	if err := authz.Authorize(rq, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err == nil {
		t.Fatal("a refresh token authorized a tool-path request")
	}
	// Rotation: the presented refresh token yields a fresh pair.
	rform := url.Values{}
	rform.Set("grant_type", "refresh_token")
	rform.Set("client_id", clientID)
	rform.Set("refresh_token", pair1.Refresh)
	rform.Set("resource", s.RouteURL)
	w4 := httptest.NewRecorder()
	rreq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(rform.Encode()))
	rreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeToken(w4, rreq)
	if w4.Code != http.StatusOK {
		t.Fatalf("refresh grant: %d body=%q", w4.Code, w4.Body.String())
	}
	var pair2 struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	_ = json.Unmarshal(w4.Body.Bytes(), &pair2)
	if pair2.Access == "" || pair2.Refresh == "" || pair2.Refresh == pair1.Refresh {
		t.Fatalf("rotation did not issue a fresh pair: %s", w4.Body.String())
	}
	// The new access token still works at admission.
	rq2r := httptest.NewRequest(http.MethodPost, s.RouteURL, nil)
	rq2r.Header.Set("Authorization", "Bearer "+pair2.Access)
	if err := authz.Authorize(rq2r, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("rotated access token denied: %v", err)
	}
	// Replay of the rotated-out token fails closed (RFC 6749 §6).
	rform.Set("refresh_token", pair1.Refresh)
	w5 := httptest.NewRecorder()
	rreq5 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(rform.Encode()))
	rreq5.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeToken(w5, rreq5)
	if w5.Code == http.StatusOK {
		t.Fatal("a rotated-out refresh token was accepted (no replay detection)")
	}
	// The operator's client revocation terminates the lineage.
	if err := store.RevokeClient(clientID); err != nil {
		t.Fatal(err)
	}
	rform.Set("refresh_token", pair2.Refresh)
	w6 := httptest.NewRecorder()
	rreq6 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(rform.Encode()))
	rreq6.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeToken(w6, rreq6)
	if w6.Code == http.StatusOK {
		t.Fatal("a revoked client still refreshed a token")
	}
}

// B: at the quota bound, safe reclamation must let a legitimate
// registration through rather than dead-ending at 429 while abandoned
// registrations occupy the table.
func TestRegistrationReclaimsAtQuota(t *testing.T) {
	s, _, _ := newTestServer(t)
	// Fill the route with abandoned registrations older than the pending
	// window.
	for i := 0; i < MaxClientsPerRoute; i++ {
		if err := s.Store.RegisterClient(Client{
			ID:        "fill-" + strconv.Itoa(i),
			Name:      "fill",
			CreatedAt: time.Now().Add(-(MaxPendingClientAge + time.Hour)),
			Tenant:    "tenant-test",
			Route:     "r-test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	body := `{"client_name":"legit","redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none"}`
	w := httptest.NewRecorder()
	s.ServeRegister(w, httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("registration at a full-but-abandoned quota: status=%d body=%s, want 201", w.Code, w.Body.String())
	}
	n, _ := s.Store.CountClients("tenant-test", "r-test")
	if n > MaxClientsPerRoute {
		t.Fatalf("reclamation overshot the bound: %d clients", n)
	}
}
