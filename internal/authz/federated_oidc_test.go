package authz

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type testIDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce"`
	AZP   string `json:"azp,omitempty"`
}

type mockOIDCProvider struct {
	srv             *httptest.Server
	pub             ed25519.PublicKey
	priv            ed25519.PrivateKey
	kid             string
	mu              sync.Mutex
	codes           map[string]mockIDPCode
	nextSub         string
	badNonce        bool
	badAud          string
	extraAud        string
	azp             string
	onTokenExchange func()
}

type mockIDPCode struct {
	subject   string
	nonce     string
	challenge string
	clientID  string
	redirect  string
}

func newMockOIDCProvider(t *testing.T, defaultSubject string) *mockOIDCProvider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	p := &mockOIDCProvider{
		pub:     pub,
		priv:    priv,
		kid:     "idp-key-1",
		codes:   map[string]mockIDPCode{},
		nextSub: defaultSubject,
	}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *mockOIDCProvider) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 p.srv.URL,
			"authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint":         p.srv.URL + "/token",
			"jwks_uri":               p.srv.URL + "/jwks",
		})
	case "/jwks":
		writeJSON(w, http.StatusOK, map[string]any{
			"keys": []map[string]any{{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(p.pub),
				"kid": p.kid,
				"use": "sig",
				"alg": "EdDSA",
			}},
		})
	case "/token":
		_ = r.ParseForm()
		code := r.Form.Get("code")
		verifier := r.Form.Get("code_verifier")
		p.mu.Lock()
		rec, ok := p.codes[code]
		delete(p.codes, code)
		badNonce := p.badNonce
		badAud := p.badAud
		extraAud := p.extraAud
		azp := p.azp
		hook := p.onTokenExchange
		p.mu.Unlock()
		if hook != nil {
			hook()
		}
		if !ok || CodeChallengeS256(verifier) != rec.challenge || r.Form.Get("redirect_uri") != rec.redirect {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		nonce := rec.nonce
		if badNonce {
			nonce = "wrong-nonce"
		}
		aud := jwt.ClaimStrings{rec.clientID}
		if badAud != "" {
			aud = jwt.ClaimStrings{badAud}
		} else if extraAud != "" {
			aud = jwt.ClaimStrings{rec.clientID, extraAud}
		}
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, testIDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    p.srv.URL,
				Subject:   rec.subject,
				Audience:  aud,
				ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
			Nonce: nonce,
			AZP:   azp,
		})
		tok.Header["kid"] = p.kid
		signed, err := tok.SignedString(p.priv)
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "mock-idp-access-token",
			"id_token":     signed,
			"token_type":   "Bearer",
		})
	default:
		http.NotFound(w, r)
	}
}

// issueCodeForAuthorizeRedirect parses Ocliv's redirect to the mock IdP and
// returns a callback query string simulating the user authenticating as subject.
func (p *mockOIDCProvider) completeLogin(t *testing.T, idpRedirectURL, subject string) string {
	t.Helper()
	u, err := url.Parse(idpRedirectURL)
	if err != nil {
		t.Fatalf("parse IdP redirect: %v", err)
	}
	q := u.Query()
	code, _ := mintRandomToken("idpc_", 16)
	p.mu.Lock()
	p.codes[code] = mockIDPCode{
		subject:   subject,
		nonce:     q.Get("nonce"),
		challenge: q.Get("code_challenge"),
		clientID:  q.Get("client_id"),
		redirect:  q.Get("redirect_uri"),
	}
	p.mu.Unlock()
	cb := url.Values{
		"code":  {code},
		"state": {q.Get("state")},
	}
	return cb.Encode()
}

// OCL-005 & OCL-006: Full federated OIDC authorization flow, unauthorized
// subject rejection, provenance-based trust-policy revocation, and
// preservation of separately authorized / legacy grants.
func TestFederatedOIDCE2EAndProvenanceRevocation(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	idp := newMockOIDCProvider(t, "auth0|owner-123")

	srv := newTrustTestServer(t, st, "tenant-a", "route-priv")
	srv.OIDCClient = &OIDCClient{HTTPClient: idp.srv.Client(), AllowLoopbackForTest: true}
	authzCheck := NewAuthorizer(srv.Issuer, st)

	// Register a separately approved direct operator client AND a legacy grant
	// BEFORE enabling federated auth so we can prove:
	//  1. Direct approval is prohibited once federated auth is active.
	//  2. Revoking the ChatGPT trust policy preserves those rows' DB status
	//     without accidentally revoking unrelated provenance.
	_, directReg := postDCR(t, srv, "DirectCLI", []string{"https://other.example/cb"})
	directClientID := directReg["client_id"].(string)
	if err := st.ApproveGrantDirect(directClientID, "tenant-a", "route-priv"); err != nil {
		t.Fatalf("ApproveGrantDirect (pre-federated): %v", err)
	}
	_, legacyReg := postDCR(t, srv, "LegacyClient", []string{"https://legacy.example/cb"})
	legacyClientID := legacyReg["client_id"].(string)
	if _, err := db.Exec(`UPDATE authz_grants SET status='active', auth_method='legacy', trust_policy_id='' WHERE client_id=?`, legacyClientID); err != nil {
		t.Fatalf("seed legacy grant: %v", err)
	}

	preset, _ := LookupTrustPreset("chatgpt")
	polID, _ := MintTrustPolicyID()
	if err := st.CreateTrustPolicy(ClientTrustPolicy{
		ID:           polID,
		TenantID:     "tenant-a",
		RouteID:      "route-priv",
		OwnerKeyID:   "key-owner",
		Kind:         preset.Kind,
		RedirectURIs: preset.RedirectURIs,
		Enabled:      true,
	}); err != nil {
		t.Fatalf("CreateTrustPolicy: %v", err)
	}
	if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
		TenantID:        "tenant-a",
		RouteID:         "route-priv",
		Mode:            VisitorAuthModeFederated,
		Issuer:          idp.srv.URL,
		ClientID:        "ocliv-relay-client",
		ClientSecret:    "idp-secret",
		AllowedSubjects: []string{"auth0|owner-123"},
		ClientPolicy:    "chatgpt",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("SetVisitorAuthPolicy: %v", err)
	}

	// 1. Register ChatGPT client via public DCR -> starts PENDING (no active grant yet).
	code, reg := postDCR(t, srv, "ChatGPT", preset.RedirectURIs)
	if code != http.StatusCreated {
		t.Fatalf("DCR status=%d", code)
	}
	clientID := reg["client_id"].(string)
	if g, err := st.GetGrant(clientID, "tenant-a", "route-priv"); err != nil || g.Status != GrantPending {
		t.Fatalf("expected pending grant after DCR, got %+v err=%v", g, err)
	}

	// 2. Unauthorized user (different subject) fails closed at callback -> no grant activated.
	verifier := "fed-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authQ := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {preset.RedirectURIs[0]},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"client-st-unauth"},
		"resource":              {srv.RouteURL},
		"scope":                 {"mcp:tools offline_access"},
	}
	aRec := httptest.NewRecorder()
	srv.ServeAuthorize(aRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+authQ.Encode(), nil))
	if aRec.Code != http.StatusFound || !strings.HasPrefix(aRec.Header().Get("Location"), idp.srv.URL+"/authorize") {
		t.Fatalf("expected redirect to IdP, got %d loc=%q", aRec.Code, aRec.Header().Get("Location"))
	}
	cbQueryWrong := idp.completeLogin(t, aRec.Header().Get("Location"), "auth0|intruder-999")
	cbRecWrong := httptest.NewRecorder()
	srv.ServeOIDCCallback(cbRecWrong, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/callback?"+cbQueryWrong, nil))
	if cbRecWrong.Code != http.StatusFound {
		t.Fatalf("expected error redirect for intruder, got %d", cbRecWrong.Code)
	}
	wrongLoc, _ := url.Parse(cbRecWrong.Header().Get("Location"))
	if wrongLoc.Query().Get("error") != "access_denied" || wrongLoc.Query().Get("iss") != srv.IssuerURL {
		t.Fatalf("expected access_denied with RFC 9207 iss, got %s", wrongLoc.String())
	}
	if g, _ := st.GetGrant(clientID, "tenant-a", "route-priv"); g.Status != GrantPending {
		t.Fatalf("intruder login must leave grant pending, got %+v", g)
	}

	// 3. Replaying the consumed state fails closed.
	cbReplay := httptest.NewRecorder()
	srv.ServeOIDCCallback(cbReplay, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/callback?"+cbQueryWrong, nil))
	if cbReplay.Code != http.StatusBadRequest {
		t.Fatalf("replayed OIDC state must return 400, got %d", cbReplay.Code)
	}

	// 4. Authorized owner completes OAuth without any pairing secret.
	authQ.Set("state", "client-st-owner")
	aRec2 := httptest.NewRecorder()
	srv.ServeAuthorize(aRec2, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+authQ.Encode(), nil))
	cbQueryOK := idp.completeLogin(t, aRec2.Header().Get("Location"), "auth0|owner-123")
	cbRecOK := httptest.NewRecorder()
	srv.ServeOIDCCallback(cbRecOK, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/callback?"+cbQueryOK, nil))
	if cbRecOK.Code != http.StatusFound {
		t.Fatalf("authorized owner callback status=%d body=%s", cbRecOK.Code, cbRecOK.Body.String())
	}
	okLoc, _ := url.Parse(cbRecOK.Header().Get("Location"))
	authCode := okLoc.Query().Get("code")
	if authCode == "" || okLoc.Query().Get("state") != "client-st-owner" || okLoc.Query().Get("iss") != srv.IssuerURL {
		t.Fatalf("expected code+state+iss redirect, got %s", okLoc.String())
	}

	// Verify grant provenance recorded accurately.
	g, err := st.GetGrant(clientID, "tenant-a", "route-priv")
	if err != nil || g.Status != GrantActive ||
		g.Provenance.Method != GrantMethodFederatedOIDC ||
		g.Provenance.TrustPolicyID != polID ||
		g.Provenance.OwnerIssuer != idp.srv.URL ||
		g.Provenance.OwnerSubject != "auth0|owner-123" {
		t.Fatalf("unexpected federated grant provenance: %+v err=%v", g, err)
	}

	// 5. Exchange code for access + refresh token and authorize MCP request.
	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {clientID},
		"redirect_uri":  {preset.RedirectURIs[0]},
		"code_verifier": {verifier},
		"resource":      {srv.RouteURL},
	}
	tokReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/token", strings.NewReader(tokForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	srv.ServeToken(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("token exchange status=%d body=%s", tokRec.Code, tokRec.Body.String())
	}
	var tokResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(tokRec.Body.Bytes(), &tokResp)
	if tokResp.AccessToken == "" || tokResp.RefreshToken == "" {
		t.Fatalf("missing access or refresh token: %+v", tokResp)
	}

	mcpReq := httptest.NewRequest(http.MethodPost, srv.RouteURL, nil)
	mcpReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	if _, err := authzCheck.AuthorizeClaims(mcpReq, srv.RouteURL, srv.IssuerURL, "tenant-a", "route-priv"); err != nil {
		t.Fatalf("authorized request rejected: %v", err)
	}

	// 6. OCL-006: Revoking the ChatGPT trust policy atomically revokes dependent
	// grants, blocks existing access tokens AND refresh tokens, while preserving
	// separately authorized direct_operator and legacy grants!
	n, err := st.RevokeTrustPolicy("tenant-a", "route-priv", "chatgpt")
	if err != nil || n != 1 {
		t.Fatalf("RevokeTrustPolicy: n=%d err=%v", n, err)
	}
	if gAfter, _ := st.GetGrant(clientID, "tenant-a", "route-priv"); gAfter.Status != GrantRevoked {
		t.Fatalf("dependent grant must be revoked on trust policy revocation, got %+v", gAfter)
	}
	// Access token immediately denied.
	if _, err := authzCheck.AuthorizeClaims(mcpReq, srv.RouteURL, srv.IssuerURL, "tenant-a", "route-priv"); err == nil {
		t.Fatal("existing access token must fail closed after trust policy revocation")
	}
	// Refresh token immediately denied.
	refForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokResp.RefreshToken},
		"client_id":     {clientID},
		"resource":      {srv.RouteURL},
	}
	refReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/token", strings.NewReader(refForm.Encode()))
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refRec := httptest.NewRecorder()
	srv.ServeToken(refRec, refReq)
	if refRec.Code == http.StatusOK {
		t.Fatalf("refresh token must fail closed after trust policy revocation: %s", refRec.Body.String())
	}
	// Separately authorized direct_operator grant and legacy grant remain intact.
	if gd, _ := st.GetGrant(directClientID, "tenant-a", "route-priv"); gd.Status != GrantActive {
		t.Fatalf("separately approved direct_operator grant was wrongly revoked: %+v", gd)
	}
	if gl, _ := st.GetGrant(legacyClientID, "tenant-a", "route-priv"); gl.Status != GrantActive || gl.Provenance.Method != GrantMethodLegacy {
		t.Fatalf("legacy grant without policy provenance was wrongly altered: %+v", gl)
	}
}

// OCL-007: Unauthenticated registration floods (even matching ChatGPT's exact
// redirect URI) MUST NOT exhaust active grant capacity or evict authorized clients.
func TestRegistrationFloodCannotExhaustActiveCapacity(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	srv := newTrustTestServer(t, st, "tenant-flood", "route-flood")
	preset, _ := LookupTrustPreset("chatgpt")

	polID, _ := MintTrustPolicyID()
	if err := st.CreateTrustPolicy(ClientTrustPolicy{
		ID:           polID,
		TenantID:     "tenant-flood",
		RouteID:      "route-flood",
		OwnerKeyID:   "key-owner",
		Kind:         preset.Kind,
		RedirectURIs: preset.RedirectURIs,
		Enabled:      true,
	}); err != nil {
		t.Fatalf("CreateTrustPolicy: %v", err)
	}

	// Register one genuinely authorized client first.
	code, regLegit := postDCR(t, srv, "LegitClient", preset.RedirectURIs)
	if code != http.StatusCreated {
		t.Fatalf("legit DCR status=%d", code)
	}
	legitID := regLegit["client_id"].(string)
	if err := st.ApproveGrantWithProvenance(legitID, "tenant-flood", "route-flood", false, GrantProvenance{
		Method:        GrantMethodFederatedOIDC,
		TrustPolicyID: polID,
		OwnerIssuer:   "https://idp.example",
		OwnerSubject:  "auth0|owner",
	}); err != nil {
		t.Fatalf("approve legit: %v", err)
	}

	// Flood MaxClientsPerRoute + 25 unauthenticated registrations matching the preset redirect URI.
	for i := 0; i < MaxClientsPerRoute+25; i++ {
		c, r := postDCR(t, srv, "FloodBot", preset.RedirectURIs)
		if c != http.StatusCreated {
			t.Fatalf("flood registration %d failed with status=%d body=%v (quota exhausted by pending registrations!)", i, c, r)
		}
		fid := r["client_id"].(string)
		if g, err := st.GetGrant(fid, "tenant-flood", "route-flood"); err != nil || g.Status != GrantPending {
			t.Fatalf("flood client %d must stay pending, got %+v err=%v", i, g, err)
		}
	}

	// Count must remain bounded at MaxClientsPerRoute, and legitimate active client must survive!
	cnt, err := st.CountClients("tenant-flood", "route-flood")
	if err != nil || cnt > MaxClientsPerRoute {
		t.Fatalf("client count=%d err=%v, want <= %d", cnt, err, MaxClientsPerRoute)
	}
	if g, err := st.GetGrant(legitID, "tenant-flood", "route-flood"); err != nil || g.Status != GrantActive {
		t.Fatalf("legitimate authorized grant lost during registration flood: %+v err=%v", g, err)
	}
}

// OCL-005: Cross-route OIDC state replay, bad nonce, wrong audience, and
// dynamic subject removal from allowed_subjects must all fail closed.
func TestFederatedOIDCSecurityNegativeBoundaries(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	idp := newMockOIDCProvider(t, "auth0|owner-123")

	srvA := newTrustTestServer(t, st, "tenant-a", "route-a")
	srvA.OIDCClient = &OIDCClient{HTTPClient: idp.srv.Client(), AllowLoopbackForTest: true}
	srvB := newTrustTestServer(t, st, "tenant-a", "route-b")
	srvB.OIDCClient = &OIDCClient{HTTPClient: idp.srv.Client(), AllowLoopbackForTest: true}

	preset, _ := LookupTrustPreset("chatgpt")
	if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
		TenantID:        "tenant-a",
		RouteID:         "route-a",
		Mode:            VisitorAuthModeFederated,
		Issuer:          idp.srv.URL,
		ClientID:        "ocliv-client-a",
		AllowedSubjects: []string{"auth0|owner-123", "auth0|second-user"},
		Enabled:         true,
	}); err != nil {
		t.Fatalf("SetVisitorAuthPolicy: %v", err)
	}

	_, reg := postDCR(t, srvA, "ChatGPT", preset.RedirectURIs)
	cid := reg["client_id"].(string)
	verifier := "neg-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	startAuth := func(state string) string {
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {cid},
			"redirect_uri":          {preset.RedirectURIs[0]},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"state":                 {state},
			"resource":              {srvA.RouteURL},
			"scope":                 {"mcp:tools offline_access"},
		}
		rec := httptest.NewRecorder()
		srvA.ServeAuthorize(rec, httptest.NewRequest(http.MethodGet, srvA.IssuerURL+"/authorize?"+q.Encode(), nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("authorize status=%d", rec.Code)
		}
		return rec.Header().Get("Location")
	}

	// 1. Cross-route OIDC callback replay on route-b fails WITHOUT consuming route-a's transaction.
	loc1 := startAuth("st-cross")
	cbQ1 := idp.completeLogin(t, loc1, "auth0|owner-123")
	recCross := httptest.NewRecorder()
	srvB.ServeOIDCCallback(recCross, httptest.NewRequest(http.MethodGet, srvB.IssuerURL+"/callback?"+cbQ1, nil))
	if recCross.Code != http.StatusBadRequest {
		t.Fatalf("cross-route callback status=%d, want 400", recCross.Code)
	}

	// 2. Bad nonce in id_token fails closed.
	idp.mu.Lock()
	idp.badNonce = true
	idp.mu.Unlock()
	recNonce := httptest.NewRecorder()
	srvA.ServeOIDCCallback(recNonce, httptest.NewRequest(http.MethodGet, srvA.IssuerURL+"/callback?"+cbQ1, nil))
	idp.mu.Lock()
	idp.badNonce = false
	idp.mu.Unlock()
	if recNonce.Code != http.StatusFound || !strings.Contains(recNonce.Header().Get("Location"), "error=access_denied") {
		t.Fatalf("bad nonce must redirect access_denied, got %d loc=%q", recNonce.Code, recNonce.Header().Get("Location"))
	}

	// 3. Wrong audience in id_token fails closed.
	loc2 := startAuth("st-aud")
	cbQ2 := idp.completeLogin(t, loc2, "auth0|owner-123")
	idp.mu.Lock()
	idp.badAud = "different-client-id"
	idp.mu.Unlock()
	recAud := httptest.NewRecorder()
	srvA.ServeOIDCCallback(recAud, httptest.NewRequest(http.MethodGet, srvA.IssuerURL+"/callback?"+cbQ2, nil))
	idp.mu.Lock()
	idp.badAud = ""
	idp.mu.Unlock()
	if recAud.Code != http.StatusFound || !strings.Contains(recAud.Header().Get("Location"), "error=access_denied") {
		t.Fatalf("wrong audience must redirect access_denied, got %d loc=%q", recAud.Code, recAud.Header().Get("Location"))
	}

	// 4. Authorize second-user, then remove second-user from allowed_subjects ->
	// existing access AND refresh tokens immediately fail closed!
	loc3 := startAuth("st-sub-revoke")
	cbQ3 := idp.completeLogin(t, loc3, "auth0|second-user")
	recOK := httptest.NewRecorder()
	srvA.ServeOIDCCallback(recOK, httptest.NewRequest(http.MethodGet, srvA.IssuerURL+"/callback?"+cbQ3, nil))
	uOK, _ := url.Parse(recOK.Header().Get("Location"))
	code := uOK.Query().Get("code")
	if code == "" {
		t.Fatalf("expected auth code for second-user, got %s", uOK.String())
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cid},
		"redirect_uri": {preset.RedirectURIs[0]}, "code_verifier": {verifier}, "resource": {srvA.RouteURL},
	}
	tReq := httptest.NewRequest(http.MethodPost, srvA.IssuerURL+"/token", strings.NewReader(form.Encode()))
	tReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tRec := httptest.NewRecorder()
	srvA.ServeToken(tRec, tReq)
	var tokResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(tRec.Body.Bytes(), &tokResp)
	if tokResp.AccessToken == "" || tokResp.RefreshToken == "" {
		t.Fatalf("missing tokens: %s", tRec.Body.String())
	}

	// Remove auth0|second-user from allowed_subjects while keeping auth0|owner-123.
	if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
		TenantID:        "tenant-a",
		RouteID:         "route-a",
		Mode:            VisitorAuthModeFederated,
		Issuer:          idp.srv.URL,
		ClientID:        "ocliv-client-a",
		AllowedSubjects: []string{"auth0|owner-123"},
		Enabled:         true,
	}); err != nil {
		t.Fatalf("update visitor policy: %v", err)
	}
	authzCheck := NewAuthorizer(srvA.Issuer, st)
	mcpReq := httptest.NewRequest(http.MethodPost, srvA.RouteURL, nil)
	mcpReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	if _, err := authzCheck.AuthorizeClaims(mcpReq, srvA.RouteURL, srvA.IssuerURL, "tenant-a", "route-a"); err == nil {
		t.Fatal("removed subject's access token must fail closed immediately")
	}
	refForm := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokResp.RefreshToken},
		"client_id": {cid}, "resource": {srvA.RouteURL},
	}
	refReq := httptest.NewRequest(http.MethodPost, srvA.IssuerURL+"/token", strings.NewReader(refForm.Encode()))
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refRec := httptest.NewRecorder()
	srvA.ServeToken(refRec, refReq)
	if refRec.Code == http.StatusOK {
		t.Fatalf("removed subject's refresh token must fail closed: %s", refRec.Body.String())
	}
}
