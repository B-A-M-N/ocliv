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

	"github.com/B-A-M-N/ocliv/internal/store"
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

func TestGoogleConfidentialPersistentLinking(t *testing.T) {
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
	s := NewServer(issuer, st, "default", "r-g", "https://relay.example/r/r-g/mcp", "https://relay.example")

	const clientID = "cli_google_persist"
	const secret = "sec_google_persist_999"
	if err := st.RegisterClient(Client{
		ID:               clientID,
		Name:             "Google Connected App",
		RedirectURIs:     []string{"https://oauth-redirect.googleusercontent.com/r/proj1"},
		CreatedAt:        time.Now(),
		Tenant:           "default",
		Route:            "r-g",
		ClientMode:       "confidential",
		ClientSecretHash: HashSecret(secret),
		RefreshPolicy:    "google_confidential",
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if err := st.ApproveGrantDirect(clientID, "default", "r-g"); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}

	verifier := "v" + strings.Repeat("p", 42)
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

	// Code exchange works even if Google omits `resource` for google_confidential.
	reqCode := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=authorization_code&code="+url.QueryEscape(code)+
			"&redirect_uri="+url.QueryEscape("https://oauth-redirect.googleusercontent.com/r/proj1")+
			"&code_verifier="+verifier))
	reqCode.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqCode.SetBasicAuth(clientID, secret)
	wCode := httptest.NewRecorder()
	s.ServeToken(wCode, reqCode)
	if wCode.Code != http.StatusOK {
		t.Fatalf("code exchange status=%d body=%s", wCode.Code, wCode.Body.String())
	}
	var tokResp map[string]any
	_ = json.Unmarshal(wCode.Body.Bytes(), &tokResp)
	rtok, _ := tokResp["refresh_token"].(string)
	if !strings.HasPrefix(rtok, "rtok_") {
		t.Fatalf("expected rtok_, got %q", rtok)
	}

	// Reopen DB (restart) and run two simultaneous refreshes + retry -> ALL succeed and echo the same rtok.
	db.Close()
	db2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	s2 := NewServer(issuer, NewSQLStore(db2.SQL()), "default", "r-g", "https://relay.example/r/r-g/mcp", "https://relay.example")

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reqRef := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
				"grant_type=refresh_token&refresh_token="+url.QueryEscape(rtok)))
			reqRef.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reqRef.SetBasicAuth(clientID, secret)
			wRef := httptest.NewRecorder()
			s2.ServeToken(wRef, reqRef)
			if wRef.Code != http.StatusOK {
				t.Errorf("google_confidential refresh status=%d body=%s", wRef.Code, wRef.Body.String())
				return
			}
			var r2 map[string]any
			_ = json.Unmarshal(wRef.Body.Bytes(), &r2)
			if got, _ := r2["refresh_token"].(string); got != rtok {
				t.Errorf("google_confidential rotated refresh_token to %q, want %q", got, rtok)
			}
		}()
	}
	wg.Wait()

	// Wrong route rejected.
	sOther := NewServer(issuer, NewSQLStore(db2.SQL()), "default", "r-other", "https://relay.example/r/r-other/mcp", "https://relay.example")
	reqOther := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rtok)))
	reqOther.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqOther.SetBasicAuth(clientID, secret)
	wOther := httptest.NewRecorder()
	sOther.ServeToken(wOther, reqOther)
	if wOther.Code != http.StatusBadRequest {
		t.Fatalf("wrong route status=%d, want 400", wOther.Code)
	}

	// Revocation blocks refresh immediately.
	if err := s2.Store.RevokeClient(clientID); err != nil {
		t.Fatalf("RevokeClient: %v", err)
	}
	reqRev := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rtok)))
	reqRev.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqRev.SetBasicAuth(clientID, secret)
	wRev := httptest.NewRecorder()
	s2.ServeToken(wRev, reqRev)
	if wRev.Code != http.StatusBadRequest {
		t.Fatalf("revoked refresh status=%d, want 400", wRev.Code)
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

func TestConfidentialRefreshPreservesLimitedScopeAndRejectsEscalation(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Issuer:    issuer,
		Store:     st,
		RouteID:   "route-scope",
		RouteURL:  "https://relay.example/r/route-scope/mcp",
		IssuerURL: "https://relay.example/r/route-scope/oauth",
		Tenant:    "default",
	}
	secret := "sec_scope_only_12345"
	clientID := "cli_scope_only"
	if err := st.RegisterClient(Client{
		ID:               clientID,
		Name:             "Scope Limited",
		RedirectURIs:     []string{"https://oauth-redirect.googleusercontent.com/r/app"},
		Tenant:           "default",
		Route:            "route-scope",
		ClientMode:       "confidential",
		ClientSecretHash: HashSecret(secret),
		RefreshPolicy:    "google_confidential",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApproveGrantDirect(clientID, "default", "route-scope"); err != nil {
		t.Fatal(err)
	}
	verifier := "v" + strings.Repeat("s", 42)
	if err := st.CreateCode(Code{
		Code: "code-scope", ClientID: clientID, Tenant: "default", Route: "route-scope",
		RedirectURI: "https://oauth-redirect.googleusercontent.com/r/app",
		Challenge:   CodeChallengeS256(verifier), ChallengeMethod: "S256",
		Scope: "offline_access", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=authorization_code&code=code-scope&redirect_uri="+url.QueryEscape("https://oauth-redirect.googleusercontent.com/r/app")+"&code_verifier="+verifier))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	s.ServeToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("code exchange=%d body=%s", w.Code, w.Body.String())
	}
	var tokResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &tokResp)
	rtok, _ := tokResp["refresh_token"].(string)
	if rtok == "" {
		t.Fatal("missing refresh token")
	}

	// Refresh and verify mcp:tools is NOT granted.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rtok)))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.SetBasicAuth(clientID, secret)
	s.ServeToken(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("refresh=%d body=%s", w2.Code, w2.Body.String())
	}
	var refResp map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &refResp)
	if got, _ := refResp["scope"].(string); got != "offline_access" {
		t.Fatalf("refreshed scope=%q, want offline_access only", got)
	}
	accessTok, _ := refResp["access_token"].(string)
	az := NewAuthorizer(issuer, st)
	mcpReq := httptest.NewRequest(http.MethodPost, "/r/route-scope/mcp", nil)
	mcpReq.Header.Set("Authorization", "Bearer "+accessTok)
	if err := az.Authorize(mcpReq, s.RouteURL, s.IssuerURL, "default", "route-scope"); err == nil {
		t.Fatal("expected Authorizer to reject offline_access-only token")
	}

	// Empty-scope managed token must also be rejected.
	emptyTok, err := issuer.Mint(TokenClaims{
		Issuer: s.IssuerURL, Subject: clientID, Audience: s.RouteURL,
		Tenant: "default", Route: "route-scope", Scope: "",
		Expiry: time.Now().Add(time.Minute).Unix(), ID: "jti-empty",
	})
	if err != nil {
		t.Fatal(err)
	}
	emptyReq := httptest.NewRequest(http.MethodPost, "/r/route-scope/mcp", nil)
	emptyReq.Header.Set("Authorization", "Bearer "+emptyTok)
	if err := az.Authorize(emptyReq, s.RouteURL, s.IssuerURL, "default", "route-scope"); err == nil {
		t.Fatal("expected Authorizer to reject empty-scope token")
	}
}

func TestServeRevokeRevokesOpaqueRefreshToken(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Issuer:    issuer,
		Store:     st,
		RouteID:   "route-rev",
		RouteURL:  "https://relay.example/r/route-rev/mcp",
		IssuerURL: "https://relay.example/r/route-rev/oauth",
		Tenant:    "default",
	}
	secret := "sec_rev_12345"
	clientID := "cli_rev"
	_ = st.RegisterClient(Client{
		ID: clientID, Name: "Rev", RedirectURIs: []string{"https://oauth-redirect.googleusercontent.com/r/app"},
		Tenant: "default", Route: "route-rev", ClientMode: "confidential",
		ClientSecretHash: HashSecret(secret), RefreshPolicy: "google_confidential",
	})
	_ = st.ApproveGrantDirect(clientID, "default", "route-rev")
	rtok := "rtok_test_opaque_123456"
	now := time.Now().UTC()
	_ = st.CreateOpaqueRefresh(OpaqueRefresh{
		TokenHash: HashSecret(rtok), ClientID: clientID, Tenant: "default", Route: "route-rev",
		Scope: "mcp:tools offline_access", ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour), LastUsedAt: now,
	})

	// Google-initiated revocation of rtok_...
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader("token="+url.QueryEscape(rtok)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeRevoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ServeRevoke=%d, want 200", w.Code)
	}

	// Subsequent refresh must fail.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=refresh_token&refresh_token="+url.QueryEscape(rtok)))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.SetBasicAuth(clientID, secret)
	s.ServeToken(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("refresh after ServeRevoke=%d, want 400", w2.Code)
	}
}
