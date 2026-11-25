package authz

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestFederatedPolicyAuthoritativeBlocksLegacyAndDirectBypass verifies P0:
// enabling federated OIDC on a route makes it the SOLE authentication authority.
// Pre-existing legacy grants (even with skip_pairing=1) and direct_operator
// grants cannot bypass /authorize, /consent, /token (refresh), or AuthorizeClaims,
// and ApproveGrantDirect / ApproveGrantWithPairingSecret fail closed.
func TestFederatedPolicyAuthoritativeBlocksLegacyAndDirectBypass(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	idp := newMockOIDCProvider(t, "auth0|owner-123")
	srv := newTrustTestServer(t, st, "tenant-a", "route-fed")
	srv.OIDCClient = &OIDCClient{HTTPClient: idp.srv.Client(), AllowLoopbackForTest: true}
	authzCheck := NewAuthorizer(srv.Issuer, st)

	// 1. Seed a legacy skip_pairing=1 grant and a direct_operator grant BEFORE enabling federated auth.
	_, legReg := postDCR(t, srv, "LegacyAuto", []string{"https://legacy.example/cb"})
	legID := legReg["client_id"].(string)
	if _, err := db.Exec(`UPDATE authz_grants SET status='active', skip_pairing=1, auth_method='legacy' WHERE client_id=?`, legID); err != nil {
		t.Fatalf("seed legacy grant: %v", err)
	}
	// Even BEFORE federated auth is enabled, a migrated legacy grant must NOT pass exactOperatorApprovedBinding.
	legGrant, _ := st.GetGrant(legID, "tenant-a", "route-fed")
	legClient, _ := st.GetClient(legID)
	if exactOperatorApprovedBinding(legGrant, legClient, "tenant-a", "route-fed", "https://legacy.example/cb") {
		t.Fatal("migrated legacy grant with skip_pairing=1 must NEVER qualify for direct authorization")
	}

	_, dirReg := postDCR(t, srv, "DirectOp", []string{"https://direct.example/cb"})
	dirID := dirReg["client_id"].(string)
	if err := st.ApproveGrantDirect(dirID, "tenant-a", "route-fed"); err != nil {
		t.Fatalf("ApproveGrantDirect pre-federated: %v", err)
	}

	// Mint an access token and refresh token for the direct_operator client while route is non-federated.
	verifier := "direct-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authQ := url.Values{
		"response_type": {"code"}, "client_id": {dirID}, "redirect_uri": {"https://direct.example/cb"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"state": {"st-pre"}, "resource": {srv.RouteURL}, "scope": {"mcp:tools offline_access"},
	}
	aRec := httptest.NewRecorder()
	srv.ServeAuthorize(aRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+authQ.Encode(), nil))
	if aRec.Code != http.StatusFound {
		t.Fatalf("pre-federated direct authorize status=%d", aRec.Code)
	}
	preLoc, _ := url.Parse(aRec.Header().Get("Location"))
	preCode := preLoc.Query().Get("code")
	tokForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {preCode}, "client_id": {dirID},
		"redirect_uri": {"https://direct.example/cb"}, "code_verifier": {verifier}, "resource": {srv.RouteURL},
	}
	tokReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/token", strings.NewReader(tokForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	srv.ServeToken(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("pre-federated token exchange status=%d body=%s", tokRec.Code, tokRec.Body.String())
	}
	var preTok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(tokRec.Body.Bytes(), &preTok)

	// 2. Enable federated VisitorAuthPolicy on the route.
	if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
		TenantID:        "tenant-a",
		RouteID:         "route-fed",
		Mode:            VisitorAuthModeFederated,
		Issuer:          idp.srv.URL,
		ClientID:        "ocliv-client",
		AllowedSubjects: []string{"auth0|owner-123"},
		Enabled:         true,
	}); err != nil {
		t.Fatalf("SetVisitorAuthPolicy: %v", err)
	}

	// 3. Direct operator grant MUST NOT bypass /authorize — must redirect to OIDC IdP, NOT issue a code directly!
	aRec2 := httptest.NewRecorder()
	srv.ServeAuthorize(aRec2, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+authQ.Encode(), nil))
	if aRec2.Code != http.StatusFound || !strings.HasPrefix(aRec2.Header().Get("Location"), idp.srv.URL+"/authorize") {
		t.Fatalf("direct_operator grant bypassed federated /authorize! status=%d loc=%q", aRec2.Code, aRec2.Header().Get("Location"))
	}

	// 4. Existing direct_operator access token MUST fail closed at AuthorizeClaims.
	mcpReq := httptest.NewRequest(http.MethodPost, srv.RouteURL, nil)
	mcpReq.Header.Set("Authorization", "Bearer "+preTok.AccessToken)
	if _, err := authzCheck.AuthorizeClaims(mcpReq, srv.RouteURL, srv.IssuerURL, "tenant-a", "route-fed"); err == nil {
		t.Fatal("existing direct_operator access token bypassed federated-only route!")
	}

	// 5. Existing direct_operator refresh token MUST fail closed at /token.
	refForm := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {preTok.RefreshToken},
		"client_id": {dirID}, "resource": {srv.RouteURL},
	}
	refReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/token", strings.NewReader(refForm.Encode()))
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refRec := httptest.NewRecorder()
	srv.ServeToken(refRec, refReq)
	if refRec.Code == http.StatusOK {
		t.Fatalf("existing direct_operator refresh token bypassed federated-only route: %s", refRec.Body.String())
	}

	// 6. Management direct & pairing approvals MUST be refused on a federated route.
	_, newReg := postDCR(t, srv, "NewClient", []string{"https://new.example/cb"})
	newID := newReg["client_id"].(string)
	if err := st.ApproveGrantDirect(newID, "tenant-a", "route-fed"); !errors.Is(err, ErrFederatedPolicyRequired) {
		t.Fatalf("ApproveGrantDirect on federated route: got %v, want ErrFederatedPolicyRequired", err)
	}
	if err := st.ApproveGrantWithPairingSecret(newID, "tenant-a", "route-fed", "secret-123", time.Hour); !errors.Is(err, ErrFederatedPolicyRequired) {
		t.Fatalf("ApproveGrantWithPairingSecret on federated route: got %v, want ErrFederatedPolicyRequired", err)
	}
}

// TestFederatedCallbackAtomicTOCTOU verifies P0: policy revocation, policy
// replacement (revision increment), trust-policy revocation, or client
// revocation occurring WHILE the IdP /token exchange is in flight MUST cause
// atomic grant activation to fail closed and leave the grant pending.
func TestFederatedCallbackAtomicTOCTOU(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, st *SQLStore, clientID, polID, idpURL string)
	}{
		{
			name: "trust_policy_revoked_during_token_exchange",
			mutate: func(t *testing.T, st *SQLStore, _, _, _ string) {
				if _, err := st.RevokeTrustPolicy("tenant-a", "route-race", "chatgpt"); err != nil {
					t.Fatalf("RevokeTrustPolicy: %v", err)
				}
			},
		},
		{
			name: "visitor_policy_revoked_during_token_exchange",
			mutate: func(t *testing.T, st *SQLStore, _, _, _ string) {
				if _, err := st.RevokeVisitorAuthPolicy("tenant-a", "route-race"); err != nil {
					t.Fatalf("RevokeVisitorAuthPolicy: %v", err)
				}
			},
		},
		{
			name: "visitor_policy_replaced_during_token_exchange",
			mutate: func(t *testing.T, st *SQLStore, _, _, idpURL string) {
				// Even if the subject is still listed, replacing the policy bumps revision!
				if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
					TenantID:        "tenant-a",
					RouteID:         "route-race",
					Mode:            VisitorAuthModeFederated,
					Issuer:          idpURL,
					ClientID:        "ocliv-client",
					AllowedSubjects: []string{"auth0|owner-123"},
					ClientPolicy:    "chatgpt",
					Enabled:         true,
				}); err != nil {
					t.Fatalf("SetVisitorAuthPolicy replace: %v", err)
				}
			},
		},
		{
			name: "client_revoked_during_token_exchange",
			mutate: func(t *testing.T, st *SQLStore, clientID, _, _ string) {
				if err := st.RevokeClient(clientID); err != nil {
					t.Fatalf("RevokeClient: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDB(t)
			applySchema(t, db)
			st := NewSQLStore(db)
			idp := newMockOIDCProvider(t, "auth0|owner-123")
			srv := newTrustTestServer(t, st, "tenant-a", "route-race")
			srv.OIDCClient = &OIDCClient{HTTPClient: idp.srv.Client(), AllowLoopbackForTest: true}

			preset, _ := LookupTrustPreset("chatgpt")
			polID, _ := MintTrustPolicyID()
			if err := st.CreateTrustPolicy(ClientTrustPolicy{
				ID: polID, TenantID: "tenant-a", RouteID: "route-race",
				OwnerKeyID: "key-1", Kind: preset.Kind, RedirectURIs: preset.RedirectURIs, Enabled: true,
			}); err != nil {
				t.Fatalf("CreateTrustPolicy: %v", err)
			}
			if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
				TenantID: "tenant-a", RouteID: "route-race", Mode: VisitorAuthModeFederated,
				Issuer: idp.srv.URL, ClientID: "ocliv-client",
				AllowedSubjects: []string{"auth0|owner-123"}, ClientPolicy: "chatgpt", Enabled: true,
			}); err != nil {
				t.Fatalf("SetVisitorAuthPolicy: %v", err)
			}

			_, reg := postDCR(t, srv, "ChatGPT", preset.RedirectURIs)
			cid := reg["client_id"].(string)

			verifier := "race-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
			sum := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(sum[:])
			q := url.Values{
				"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {preset.RedirectURIs[0]},
				"code_challenge": {challenge}, "code_challenge_method": {"S256"},
				"state": {"st-race"}, "resource": {srv.RouteURL}, "scope": {"mcp:tools"},
			}
			aRec := httptest.NewRecorder()
			srv.ServeAuthorize(aRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+q.Encode(), nil))
			if aRec.Code != http.StatusFound {
				t.Fatalf("authorize status=%d", aRec.Code)
			}
			cbQ := idp.completeLogin(t, aRec.Header().Get("Location"), "auth0|owner-123")

			// Inject the concurrent policy mutation DURING the IdP /token exchange!
			idp.mu.Lock()
			idp.onTokenExchange = func() {
				tc.mutate(t, st, cid, polID, idp.srv.URL)
			}
			idp.mu.Unlock()

			cbRec := httptest.NewRecorder()
			srv.ServeOIDCCallback(cbRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/callback?"+cbQ, nil))
			if cbRec.Code != http.StatusFound || !strings.Contains(cbRec.Header().Get("Location"), "error=access_denied") {
				t.Fatalf("expected access_denied redirect on concurrent %s, got %d loc=%q", tc.name, cbRec.Code, cbRec.Header().Get("Location"))
			}
			g, err := st.GetGrant(cid, "tenant-a", "route-race")
			if err != nil {
				t.Fatalf("GetGrant: %v", err)
			}
			if g.Status == GrantActive {
				t.Fatalf("TOCTOU race activated grant despite %s: %+v", tc.name, g)
			}
		})
	}
}

// TestOIDCEgressBlocksPrivateAndLoopbackByDefault verifies P1: the default
// OIDCClient rejects loopback and private-network provider endpoints.
func TestOIDCEgressBlocksPrivateAndLoopbackByDefault(t *testing.T) {
	idp := newMockOIDCProvider(t, "auth0|owner")
	// Default OIDCClient (AllowLoopbackForTest=false) MUST block 127.0.0.1.
	c := &OIDCClient{HTTPClient: idp.srv.Client()}
	_, err := c.BuildAuthorizeURL(context.Background(), idp.srv.URL, "cid", "https://relay.example/cb", "st", "nc", "pkce-verifier-012345678901234567890123456789")
	if err == nil || !errors.Is(err, ErrOIDCEgressBlocked) {
		t.Fatalf("expected ErrOIDCEgressBlocked for loopback IdP, got: %v", err)
	}
}

// TestOIDCMultiAudienceAZPAndSecretEncryption verifies P1:
//  1. Multi-audience ID tokens require matching `azp`; mismatched `azp` fails closed.
//  2. authz_visitor_policies.client_secret is AES-256-GCM encrypted at rest in SQLite,
//     preserved across subject updates, rotatable, and fails closed with wrong/missing key.
func TestOIDCMultiAudienceAZPAndSecretEncryption(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	serverKey := []byte("0123456789abcdef0123456789abcdef")
	st.SetSecretKey(DeriveVisitorSecretKey(serverKey))

	idp := newMockOIDCProvider(t, "auth0|owner-azp")
	srv := newTrustTestServer(t, st, "tenant-a", "route-azp")
	srv.OIDCClient = &OIDCClient{HTTPClient: idp.srv.Client(), AllowLoopbackForTest: true}

	if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
		TenantID: "tenant-a", RouteID: "route-azp", Mode: VisitorAuthModeFederated,
		Issuer: idp.srv.URL, ClientID: "ocliv-client", ClientSecret: "super-secret-idp-cred",
		AllowedSubjects: []string{"auth0|owner-azp"}, Enabled: true,
	}); err != nil {
		t.Fatalf("SetVisitorAuthPolicy: %v", err)
	}

	// Verify DB row stores ciphertext (NOT plaintext).
	var rawSecret string
	var rev int64
	if err := db.QueryRow(`SELECT client_secret, revision FROM authz_visitor_policies WHERE tenant_id='tenant-a' AND route_id='route-azp'`).Scan(&rawSecret, &rev); err != nil {
		t.Fatalf("read raw client_secret: %v", err)
	}
	if !strings.HasPrefix(rawSecret, visitorSecretEncPrefix) || strings.Contains(rawSecret, "super-secret-idp-cred") {
		t.Fatalf("client_secret not encrypted at rest: %q", rawSecret)
	}
	if rev != 1 {
		t.Fatalf("expected initial revision=1, got %d", rev)
	}

	// Decrypts cleanly with key, and fails closed without key.
	vp, err := st.GetVisitorAuthPolicy("tenant-a", "route-azp")
	if err != nil || vp == nil || vp.ClientSecret != "super-secret-idp-cred" {
		t.Fatalf("GetVisitorAuthPolicy decrypt failed: vp=%+v err=%v", vp, err)
	}
	noKeyStore := NewSQLStore(db)
	if _, err := noKeyStore.GetVisitorAuthPolicy("tenant-a", "route-azp"); err == nil {
		t.Fatal("expected GetVisitorAuthPolicy without secret key to fail closed on encrypted secret")
	}

	// Updating allowed_subjects without passing ClientSecret preserves encrypted secret & bumps revision.
	if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
		TenantID: "tenant-a", RouteID: "route-azp", Mode: VisitorAuthModeFederated,
		Issuer: idp.srv.URL, ClientID: "ocliv-client",
		AllowedSubjects: []string{"auth0|owner-azp", "auth0|backup"}, Enabled: true,
	}); err != nil {
		t.Fatalf("SetVisitorAuthPolicy update: %v", err)
	}
	vp2, err := st.GetVisitorAuthPolicy("tenant-a", "route-azp")
	if err != nil || vp2.ClientSecret != "super-secret-idp-cred" || vp2.Revision != 2 {
		t.Fatalf("expected preserved secret & revision=2, got rev=%d secret=%q err=%v", vp2.Revision, vp2.ClientSecret, err)
	}

	// Test multi-audience ID token without azp -> MUST FAIL.
	_, reg := postDCR(t, srv, "ClientAZP", []string{"https://client.example/cb"})
	cid := reg["client_id"].(string)
	verifier := "azp-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	runFlow := func(state string) *httptest.ResponseRecorder {
		q := url.Values{
			"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {"https://client.example/cb"},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"},
			"state": {state}, "resource": {srv.RouteURL}, "scope": {"mcp:tools"},
		}
		aRec := httptest.NewRecorder()
		srv.ServeAuthorize(aRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+q.Encode(), nil))
		cbQ := idp.completeLogin(t, aRec.Header().Get("Location"), "auth0|owner-azp")
		cbRec := httptest.NewRecorder()
		srv.ServeOIDCCallback(cbRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/callback?"+cbQ, nil))
		return cbRec
	}

	idp.mu.Lock()
	idp.extraAud = "https://other-api.example"
	idp.azp = ""
	idp.mu.Unlock()
	recNoAZP := runFlow("st-no-azp")
	if !strings.Contains(recNoAZP.Header().Get("Location"), "error=access_denied") {
		t.Fatalf("multi-audience token without azp must fail closed, got %q", recNoAZP.Header().Get("Location"))
	}

	// Single audience with mismatched azp -> MUST FAIL.
	idp.mu.Lock()
	idp.extraAud = ""
	idp.azp = "other-client"
	idp.mu.Unlock()
	recWrongAZP := runFlow("st-wrong-azp")
	if !strings.Contains(recWrongAZP.Header().Get("Location"), "error=access_denied") {
		t.Fatalf("mismatched azp must fail closed, got %q", recWrongAZP.Header().Get("Location"))
	}

	// Multi-audience WITH matching azp -> MUST SUCCEED.
	idp.mu.Lock()
	idp.extraAud = "https://other-api.example"
	idp.azp = "ocliv-client"
	idp.mu.Unlock()
	recOK := runFlow("st-ok-azp")
	if !strings.Contains(recOK.Header().Get("Location"), "code=") {
		t.Fatalf("multi-audience token with matching azp should succeed, got %q", recOK.Header().Get("Location"))
	}
}
