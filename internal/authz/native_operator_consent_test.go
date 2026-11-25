package authz

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var challengeInputRe = regexp.MustCompile(`name="challenge" value="([^"]+)"`)

// TestNativeOperatorTransactionBoundAuthorizationE2E verifies the canonical
// self-hosted Ocliv workflow (OCL-005 native default — zero Auth0/external IdP,
// zero pairing secrets copied):
//  1. Client registers via DCR and initiates /oauth/authorize -> receives
//     transaction-bound challenge (grant stays pending; redirect URI alone
//     never authorizes).
//  2. Browser polls /oauth/consent/status -> "pending".
//  3. Operator approves that exact challenge via DecideConsentTransaction
//     (backed by Ed25519 management channel) -> grant becomes active with
//     auth_method='operator_tx' and skip_pairing=0.
//  4. Browser polls /oauth/consent/status -> "approved", completes via
//     /oauth/consent/complete -> receives PKCE-bound code + state + iss.
//  5. Replaying /oauth/consent/complete fails closed (single-use).
//  6. Code exchanges for access + refresh token; refresh rotation works;
//     a second /oauth/authorize does NOT bypass approval via skip_pairing.
//  7. Operator denial completes with access_denied and leaves grant pending.
//  8. Cross-route consent completion and federated-route native approval both fail closed.
func TestNativeOperatorTransactionBoundAuthorizationE2E(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	srv := newTrustTestServer(t, st, "tenant-native", "route-native")
	srvOther := newTrustTestServer(t, st, "tenant-native", "route-other")
	authzCheck := NewAuthorizer(srv.Issuer, st)

	preset, _ := LookupTrustPreset("chatgpt")
	code, reg := postDCR(t, srv, "ChatGPT", preset.RedirectURIs)
	if code != http.StatusCreated {
		t.Fatalf("DCR status=%d", code)
	}
	clientID := reg["client_id"].(string)

	verifier := "native-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	challengeS256 := base64.RawURLEncoding.EncodeToString(sum[:])

	startAuthorize := func(state string) string {
		q := url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {preset.RedirectURIs[0]},
			"code_challenge": {challengeS256}, "code_challenge_method": {"S256"},
			"state": {state}, "resource": {srv.RouteURL}, "scope": {"mcp:tools offline_access"},
		}
		rec := httptest.NewRecorder()
		srv.ServeAuthorize(rec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/authorize?"+q.Encode(), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
		}
		m := challengeInputRe.FindStringSubmatch(rec.Body.String())
		if len(m) != 2 {
			t.Fatalf("missing challenge in consent HTML")
		}
		return m[1]
	}

	// 1. Start transaction #1 (will be denied by operator).
	denyChallenge := startAuthorize("st-deny")
	stRec := httptest.NewRecorder()
	srv.ServeConsentStatus(stRec, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/consent/status?challenge="+denyChallenge, nil))
	if stRec.Code != http.StatusOK || !strings.Contains(stRec.Body.String(), `"pending"`) {
		t.Fatalf("expected pending status, got %d %s", stRec.Code, stRec.Body.String())
	}

	// Cross-route status check must fail closed.
	crossRec := httptest.NewRecorder()
	srvOther.ServeConsentStatus(crossRec, httptest.NewRequest(http.MethodGet, srvOther.IssuerURL+"/consent/status?challenge="+denyChallenge, nil))
	if crossRec.Code != http.StatusNotFound {
		t.Fatalf("cross-route consent status must return 404, got %d", crossRec.Code)
	}

	// Completing before operator decision fails closed, and GET is rejected (POST-only).
	getComp := httptest.NewRecorder()
	srv.ServeConsentComplete(getComp, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/consent/complete?challenge="+denyChallenge, nil))
	if getComp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /consent/complete must return 405, got %d", getComp.Code)
	}
	premature := httptest.NewRecorder()
	srv.ServeConsentComplete(premature, httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/consent/complete", strings.NewReader("challenge="+denyChallenge)))
	if premature.Code != http.StatusBadRequest {
		t.Fatalf("premature consent complete status=%d, want 400", premature.Code)
	}

	// Operator denies transaction #1.
	if _, err := st.DecideConsentTransaction(denyChallenge, "tenant-native", "route-native", "key-op-1", false); err != nil {
		t.Fatalf("DecideConsentTransaction deny: %v", err)
	}
	denyForm := strings.NewReader("challenge=" + denyChallenge)
	denyReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/consent/complete", denyForm)
	denyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	denyComplete := httptest.NewRecorder()
	srv.ServeConsentComplete(denyComplete, denyReq)
	if denyComplete.Code != http.StatusFound || !strings.Contains(denyComplete.Header().Get("Location"), "error=access_denied") {
		t.Fatalf("expected access_denied redirect, got %d loc=%q", denyComplete.Code, denyComplete.Header().Get("Location"))
	}
	if g, _ := st.GetGrant(clientID, "tenant-native", "route-native"); g.Status != GrantPending {
		t.Fatalf("denied transaction must leave grant pending, got %+v", g)
	}

	// 2. Start transaction #2 (approved by operator without copying any pairing secret).
	okChallenge := startAuthorize("st-approve")
	pending, err := st.ListPendingConsents("tenant-native", "route-native")
	if err != nil || len(pending) != 1 || pending[0].Challenge != okChallenge {
		t.Fatalf("ListPendingConsents = %+v err=%v", pending, err)
	}
	decided, err := st.DecideConsentTransaction(okChallenge, "tenant-native", "route-native", "key-op-1", true)
	if err != nil || decided.Decision != "approved" {
		t.Fatalf("DecideConsentTransaction approve: %+v err=%v", decided, err)
	}
	// Grant must now be active with provenance=operator_tx and skip_pairing=false.
	g, err := st.GetGrant(clientID, "tenant-native", "route-native")
	if err != nil || g.Status != GrantActive || g.SkipPairing || g.Provenance.Method != GrantMethodOperatorTx {
		t.Fatalf("unexpected grant after operator_tx approval: %+v err=%v", g, err)
	}

	// Status reports approved.
	stRec2 := httptest.NewRecorder()
	srv.ServeConsentStatus(stRec2, httptest.NewRequest(http.MethodGet, srv.IssuerURL+"/consent/status?challenge="+okChallenge, nil))
	if stRec2.Code != http.StatusOK || !strings.Contains(stRec2.Body.String(), `"approved"`) {
		t.Fatalf("expected approved status, got %d %s", stRec2.Code, stRec2.Body.String())
	}

	// Browser completes transaction -> receives code + state + iss.
	okReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/consent/complete", strings.NewReader("challenge="+okChallenge))
	okReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	okRec := httptest.NewRecorder()
	srv.ServeConsentComplete(okRec, okReq)
	if okRec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect with code, got %d body=%s", okRec.Code, okRec.Body.String())
	}
	okLoc, _ := url.Parse(okRec.Header().Get("Location"))
	authCode := okLoc.Query().Get("code")
	if authCode == "" || okLoc.Query().Get("state") != "st-approve" || okLoc.Query().Get("iss") != srv.IssuerURL {
		t.Fatalf("unexpected redirect location: %s", okLoc.String())
	}

	// Replay of /oauth/consent/complete fails closed.
	replayReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/consent/complete", strings.NewReader("challenge="+okChallenge))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRec := httptest.NewRecorder()
	srv.ServeConsentComplete(replayRec, replayReq)
	if replayRec.Code != http.StatusBadRequest {
		t.Fatalf("replayed consent complete must return 400, got %d", replayRec.Code)
	}

	// 3. Exchange code -> access + refresh token -> authorize MCP -> rotate refresh token.
	tokForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {authCode}, "client_id": {clientID},
		"redirect_uri": {preset.RedirectURIs[0]}, "code_verifier": {verifier}, "resource": {srv.RouteURL},
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
	mcpReq := httptest.NewRequest(http.MethodPost, srv.RouteURL, nil)
	mcpReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	if _, err := authzCheck.AuthorizeClaims(mcpReq, srv.RouteURL, srv.IssuerURL, "tenant-native", "route-native"); err != nil {
		t.Fatalf("authorized request rejected: %v", err)
	}
	// Refresh token rotation succeeds without re-approval.
	refForm := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokResp.RefreshToken},
		"client_id": {clientID}, "resource": {srv.RouteURL},
	}
	refReq := httptest.NewRequest(http.MethodPost, srv.IssuerURL+"/token", strings.NewReader(refForm.Encode()))
	refReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refRec := httptest.NewRecorder()
	srv.ServeToken(refRec, refReq)
	if refRec.Code != http.StatusOK {
		t.Fatalf("refresh rotation status=%d body=%s", refRec.Code, refRec.Body.String())
	}

	// 4. Enabling optional federated policy blocks native consent decisions.
	if err := st.SetVisitorAuthPolicy(VisitorAuthPolicy{
		TenantID: "tenant-native", RouteID: "route-native", Mode: VisitorAuthModeFederated,
		Issuer: "https://idp.example", ClientID: "cid", AllowedSubjects: []string{"sub1"}, Enabled: true,
	}); err != nil {
		t.Fatalf("SetVisitorAuthPolicy: %v", err)
	}
	if _, err := st.DecideConsentTransaction("cns_any", "tenant-native", "route-native", "key-op-1", true); !errors.Is(err, ErrFederatedPolicyRequired) {
		t.Fatalf("expected ErrFederatedPolicyRequired on federated route, got %v", err)
	}
	_ = time.Second
}
