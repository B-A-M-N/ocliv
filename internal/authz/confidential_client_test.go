package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ocliv/internal/store"
)

func TestConfidentialClientPersistentOpaqueRefresh(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ocliv.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st := NewSQLStore(db.SQL())
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s := NewServer(issuer, st, "default", "r-conf", "https://relay.example/r/r-conf/mcp", "https://relay.example")

	const clientID = "cli_google_conf"
	const secret = "sec_super_secret_12345"
	if err := st.RegisterClient(Client{
		ID:               clientID,
		Name:             "Google Connected App",
		RedirectURIs:     []string{"https://oauth-redirect.googleusercontent.com/r/proj1"},
		CreatedAt:        time.Now(),
		Tenant:           "default",
		Route:            "r-conf",
		ClientMode:       "confidential",
		ClientSecretHash: HashSecret(secret),
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if err := st.ApproveGrantDirect(clientID, "default", "r-conf"); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}

	verifier := "v" + strings.Repeat("g", 42)
	authURL := "/oauth/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("https://oauth-redirect.googleusercontent.com/r/proj1") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=st1&resource=" + url.QueryEscape(s.RouteURL)
	wAuth := httptest.NewRecorder()
	s.ServeAuthorize(wAuth, httptest.NewRequest(http.MethodGet, authURL, nil))
	if wAuth.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", wAuth.Code, wAuth.Body.String())
	}
	loc, _ := url.Parse(wAuth.Header().Get("Location"))
	code := loc.Query().Get("code")

	// Wrong secret must be rejected with 401 without consuming the code.
	badForm := "grant_type=authorization_code&code=" + url.QueryEscape(code) +
		"&client_id=" + clientID + "&client_secret=wrong" +
		"&redirect_uri=" + url.QueryEscape("https://oauth-redirect.googleusercontent.com/r/proj1") +
		"&code_verifier=" + verifier + "&resource=" + url.QueryEscape(s.RouteURL)
	reqBad := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(badForm))
	reqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wBad := httptest.NewRecorder()
	s.ServeToken(wBad, reqBad)
	if wBad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret status=%d, want 401", wBad.Code)
	}

	// Valid secret via Basic Auth exchanges code for access + opaque refresh token.
	goodForm := "grant_type=authorization_code&code=" + url.QueryEscape(code) +
		"&redirect_uri=" + url.QueryEscape("https://oauth-redirect.googleusercontent.com/r/proj1") +
		"&code_verifier=" + verifier + "&resource=" + url.QueryEscape(s.RouteURL)
	reqGood := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(goodForm))
	reqGood.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqGood.SetBasicAuth(clientID, secret)
	wGood := httptest.NewRecorder()
	s.ServeToken(wGood, reqGood)
	if wGood.Code != http.StatusOK {
		t.Fatalf("code exchange status=%d body=%s", wGood.Code, wGood.Body.String())
	}
	var tokResp map[string]any
	_ = json.Unmarshal(wGood.Body.Bytes(), &tokResp)
	rtok, _ := tokResp["refresh_token"].(string)
	if !strings.HasPrefix(rtok, "rtok_") {
		t.Fatalf("expected opaque rtok_ refresh token, got %q", rtok)
	}

	// Foreign resource on refresh must still be rejected.
	reqForeign := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rtok)+"&resource=https://evil.example/mcp"))
	reqForeign.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqForeign.SetBasicAuth(clientID, secret)
	wForeign := httptest.NewRecorder()
	s.ServeToken(wForeign, reqForeign)
	if wForeign.Code != http.StatusBadRequest {
		t.Fatalf("foreign resource status=%d, want 400", wForeign.Code)
	}

	// Simulate server restart by reopening SQLite DB; simultaneous refreshes
	// omitting `resource` rotate atomically: exactly 1 succeeds with a new
	// rtok_*, and losers fail. Replaying the burned token revokes the lineage.
	db.Close()
	db2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	s2 := NewServer(issuer, NewSQLStore(db2.SQL()), "default", "r-conf", "https://relay.example/r/r-conf/mcp", "https://relay.example")

	var (
		mu      sync.Mutex
		okCount int
		newRtok string
	)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reqRef := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
				"grant_type=refresh_token&refresh_token="+url.QueryEscape(rtok)))
			reqRef.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reqRef.SetBasicAuth(clientID, secret)
			wRef := httptest.NewRecorder()
			s2.ServeToken(wRef, reqRef)
			if wRef.Code == http.StatusOK {
				var r2 map[string]any
				_ = json.Unmarshal(wRef.Body.Bytes(), &r2)
				mu.Lock()
				okCount++
				newRtok, _ = r2["refresh_token"].(string)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if okCount != 1 || !strings.HasPrefix(newRtok, "rtok_") || newRtok == rtok {
		t.Fatalf("expected exactly 1 rotated refresh winner, got okCount=%d newRtok=%q", okCount, newRtok)
	}

	// Replaying the burned token triggers replay detection and revokes the lineage (including newRtok).
	reqReplay := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rtok)))
	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqReplay.SetBasicAuth(clientID, secret)
	wReplay := httptest.NewRecorder()
	s2.ServeToken(wReplay, reqReplay)
	if wReplay.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d, want 400", wReplay.Code)
	}
	reqLineage := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(newRtok)))
	reqLineage.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqLineage.SetBasicAuth(clientID, secret)
	wLineage := httptest.NewRecorder()
	s2.ServeToken(wLineage, reqLineage)
	if wLineage.Code != http.StatusBadRequest {
		t.Fatalf("revoked lineage status=%d, want 400", wLineage.Code)
	}

	// Client revocation immediately blocks any further refresh.
	if err := s2.Store.RevokeClient(clientID); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	reqAfter := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(newRtok)))
	reqAfter.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAfter.SetBasicAuth(clientID, secret)
	wAfter := httptest.NewRecorder()
	s2.ServeToken(wAfter, reqAfter)
	if wAfter.Code != http.StatusBadRequest {
		t.Fatalf("revoked client refresh status=%d, want 400", wAfter.Code)
	}
}

func TestScopeEnforcementAndOfflineAccess(t *testing.T) {
	s, issuer, st := newTestServer(t)
	clientID := register(t, s, "https://client.example/cb")
	if err := st.ApproveGrantDirect(clientID, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}
	// Request mcp:tools ONLY (no offline_access) -> no refresh_token issued.
	verifier := "v" + strings.Repeat("s", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("https://client.example/cb") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&scope=mcp:tools&state=st1&resource=" + url.QueryEscape(s.RouteURL)
	wAuth := httptest.NewRecorder()
	s.ServeAuthorize(wAuth, httptest.NewRequest(http.MethodGet, u, nil))
	if wAuth.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", wAuth.Code, wAuth.Body.String())
	}
	loc, _ := url.Parse(wAuth.Header().Get("Location"))
	code := loc.Query().Get("code")
	reqTok := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=authorization_code&code="+url.QueryEscape(code)+
			"&client_id="+clientID+
			"&redirect_uri="+url.QueryEscape("https://client.example/cb")+
			"&code_verifier="+verifier+
			"&resource="+url.QueryEscape(s.RouteURL)))
	reqTok.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wTok := httptest.NewRecorder()
	s.ServeToken(wTok, reqTok)
	if wTok.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", wTok.Code, wTok.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(wTok.Body.Bytes(), &resp)
	if _, hasRT := resp["refresh_token"]; hasRT {
		t.Fatalf("expected no refresh_token when offline_access was not requested, got %v", resp)
	}
	if resp["scope"] != "mcp:tools" {
		t.Fatalf("scope=%v, want mcp:tools", resp["scope"])
	}
	// Token without mcp:tools scope must be rejected by Authorizer.
	badTok, err := issuer.Mint(TokenClaims{
		Issuer:   s.IssuerURL,
		Subject:  clientID,
		Audience: s.RouteURL,
		Tenant:   s.tenant(),
		Route:    s.RouteID,
		Scope:    "offline_access",
		Expiry:   time.Now().Add(time.Hour).Unix(),
		ID:       "jti-bad-scope",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	a := NewAuthorizer(issuer, st)
	reqAuth := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+badTok)
	if err := a.Authorize(reqAuth, s.tenant(), s.RouteID, s.RouteURL, s.IssuerURL); err == nil {
		t.Fatal("Authorizer accepted token without mcp:tools scope")
	}
}

func TestAtomicDCRRollsBackOnGrantFailure(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	// Missing tenant/route triggers grant-seed failure; client row must roll back too.
	err := st.TryRegisterClientWithPendingGrant(Client{
		ID:           "cli_atomic_fail",
		Name:         "Fail",
		RedirectURIs: []string{"https://chatgpt.com/cb"},
		Tenant:       "t1",
		Route:        "r1",
	}, "", "r1")
	if err == nil {
		t.Fatal("expected error when tenant is empty")
	}
	if _, gerr := st.GetClient("cli_atomic_fail"); gerr == nil {
		t.Fatal("client row persisted despite pending-grant failure")
	}
}
