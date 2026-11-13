package authz

// Two release-gate tests for the managed authorization path:
//
//  1. Concurrent refresh attempts. The refresh grant is single-use with
//     replay rejection, so exactly ONE of several simultaneous attempts
//     with the same refresh token may succeed. If two could both win, a
//     stolen refresh token could be raced against the legitimate client.
//
//  2. Natural access-token expiry. The external qualification proved the
//     RELAY path, but a token's lifetime is enforced by the issuer's
//     verification, so the expiry itself is pinned here against a short
//     TTL: the token must stop working when it expires, and the refresh
//     grant must still work.
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

// issuedPair is one token pair as the token endpoint returns it.
type issuedPair struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Expires int    `json:"expires_in"`
}

// refreshAttempt runs one refresh grant and returns its status and body.
func refreshAttempt(t *testing.T, s *Server, clientID, refresh string) (int, issuedPair) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", refresh)
	form.Set("resource", s.RouteURL)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeToken(w, req)
	var pair issuedPair
	_ = json.Unmarshal(w.Body.Bytes(), &pair)
	return w.Code, pair
}

// TestConcurrentRefreshSingleWinner: simultaneous refresh attempts with
// the SAME refresh token must yield exactly one success. The losers must
// fail closed with invalid_grant, never with a second token pair.
func TestConcurrentRefreshSingleWinner(t *testing.T) {
	s, _, store := newTestServer(t)
	clientID := "cli-concurrent"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrantWithPairingSecret(clientID, s.tenant(), s.RouteID, "pair-c", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Mint the first pair through the code grant.
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
	form.Set("pairing_secret", "pair-c")
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
	var first issuedPair
	_ = json.Unmarshal(w3.Body.Bytes(), &first)
	if first.Refresh == "" {
		t.Fatalf("no refresh token issued: %s", w3.Body.String())
	}

	// Now race several refreshes with the same token.
	const racers = 8
	var wg sync.WaitGroup
	results := make([]int, racers)
	pairs := make([]issuedPair, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], pairs[i] = refreshAttempt(t, s, clientID, first.Refresh)
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, code := range results {
		switch code {
		case http.StatusOK:
			wins++
			if pairs[i].Access == "" || pairs[i].Refresh == "" {
				t.Fatalf("winner %d got no token pair", i)
			}
		case http.StatusBadRequest:
			var errBody struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal([]byte(strings.TrimSpace(recorderBody(t, s, clientID, first.Refresh))), &errBody)
			if errBody.Error != "invalid_grant" {
				t.Fatalf("loser %d failed with %q, want invalid_grant", i, errBody.Error)
			}
		default:
			t.Fatalf("loser %d got status %d, want 400 invalid_grant or 200", i, code)
		}
	}
	if wins != 1 {
		t.Fatalf("%d of %d concurrent refresh attempts succeeded, want exactly 1", wins, racers)
	}
}

// recorderBody re-runs one refresh grant and returns its raw body, so a
// loser's error code can be inspected.
func recorderBody(t *testing.T, s *Server, clientID, refresh string) string {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", refresh)
	form.Set("resource", s.RouteURL)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeToken(w, req)
	return w.Body.String()
}

// TestAccessTokenExpiresNaturally: with a short TTL, the access token
// must stop being admitted when it expires, and the refresh grant must
// still issue a working pair. This pins the expiry itself (not a
// simulated one) against the issuer's verification.
func TestAccessTokenExpiresNaturally(t *testing.T) {
	s, issuer, store := newTestServer(t)
	s.TokenTTL = 2 * time.Second
	clientID := "cli-expiry"
	if err := store.RegisterClient(Client{ID: clientID, Name: "c",
		RedirectURIs: []string{"http://127.0.0.1:59999/cb"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveGrantWithPairingSecret(clientID, s.tenant(), s.RouteID, "pair-e", time.Hour); err != nil {
		t.Fatal(err)
	}
	access, err := issuer.Mint(TokenClaims{
		Issuer:   s.IssuerURL,
		Subject:  clientID,
		Audience: s.RouteURL,
		Tenant:   s.tenant(),
		Route:    s.RouteID,
		Expiry:   time.Now().Add(s.TokenTTL).Unix(),
		ID:       "jti-expiry",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	authz := NewAuthorizer(issuer, store)
	req := httptest.NewRequest(http.MethodPost, s.RouteURL, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	if err := authz.Authorize(req, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("a live token was denied: %v", err)
	}
	// Let it expire for real.
	time.Sleep(s.TokenTTL + 500*time.Millisecond)
	req2 := httptest.NewRequest(http.MethodPost, s.RouteURL, nil)
	req2.Header.Set("Authorization", "Bearer "+access)
	if err := authz.Authorize(req2, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err == nil {
		t.Fatal("an EXPIRED access token was still admitted")
	}
	// The refresh grant is unaffected by the access token's expiry.
	refresh, err := issuer.Mint(TokenClaims{
		Issuer:    s.IssuerURL,
		Subject:   clientID,
		Audience:  s.RouteURL,
		Tenant:    s.tenant(),
		Route:     s.RouteID,
		Expiry:    time.Now().Add(time.Hour).Unix(),
		ID:        "jti-refresh",
		TokenType: "refresh",
	})
	if err != nil {
		t.Fatalf("mint refresh: %v", err)
	}
	code, pair := refreshAttempt(t, s, clientID, refresh)
	if code != http.StatusOK {
		t.Fatalf("refresh after access-token expiry: status %d", code)
	}
	if pair.Access == "" {
		t.Fatal("refresh issued no access token")
	}
	req3 := httptest.NewRequest(http.MethodPost, s.RouteURL, nil)
	req3.Header.Set("Authorization", "Bearer "+pair.Access)
	if err := authz.Authorize(req3, s.RouteURL, s.IssuerURL, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("the refreshed access token was denied: %v", err)
	}
}
