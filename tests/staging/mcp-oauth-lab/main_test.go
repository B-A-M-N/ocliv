package main

// OAuth lab regression tests: full authorization-code + PKCE flow and
// the negative battery. Every security gate must fail closed with no
// tool execution.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testResource = "https://public.example.org/r/routeAAA/mcp"
	testIssuer   = "https://public.example.org/r/routeAAA/oauth"
	testRedirect = "https://chatgpt.com/oauth/callback"
)

func newTestLab(t *testing.T) (*lab, *httptest.Server) {
	t.Helper()
	l := newLab("test-secret-0123456789abcdef-test-secret", testResource, "")
	srv := httptest.NewServer(newMux(l))
	t.Cleanup(srv.Close)
	return l, srv
}

func doRegister(t *testing.T, srv *httptest.Server, redirect string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{redirect},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	})
	resp, err := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: status=%d body=%s", resp.StatusCode, raw)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.ClientID == "" {
		t.Fatalf("register: bad response %s", raw)
	}
	return out.ClientID
}

func startAuthorize(t *testing.T, srv *httptest.Server, clientID, verifier, scope string) (txn, redirect string) {
	t.Helper()
	ch := s256Challenge(verifier)
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"response_type":         {"code"},
		"code_challenge":        {ch},
		"code_challenge_method": {"S256"},
		"scope":                 {scope},
		"resource":              {testResource},
		"state":                 {"st-1"},
	}
	resp, err := http.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize GET: status=%d body=%s", resp.StatusCode, raw)
	}
	s := string(raw)
	i := strings.Index(s, `name="transaction_id" value="`)
	if i < 0 {
		t.Fatalf("authorize GET: no transaction in %s", s)
	}
	rest := s[i+len(`name="transaction_id" value="`):]
	j := strings.Index(rest, `"`)
	return rest[:j], ""
}

func approveTxn(t *testing.T, srv *httptest.Server, txn string) string {
	t.Helper()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.PostForm(srv.URL+"/oauth/authorize", url.Values{
		"transaction_id": {txn},
		"decision":       {"approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve: status=%d body=%s", resp.StatusCode, raw)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != "st-1" {
		t.Fatalf("approve: state not echoed: %s", loc.String())
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("approve: no code in %s", loc.String())
	}
	return code
}

func exchangeCode(t *testing.T, srv *httptest.Server, clientID, code, verifier string) map[string]any {
	t.Helper()
	resp, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"redirect_uri":  {testRedirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out["access_token"] == "" {
		t.Fatalf("token: bad response %s", raw)
	}
	return out
}

// fullFlow runs register → authorize → approve → token and returns the
// token response.
func fullFlow(t *testing.T, srv *httptest.Server, scope string) (clientID string, tok map[string]any) {
	t.Helper()
	clientID = doRegister(t, srv, testRedirect)
	txn, _ := startAuthorize(t, srv, clientID, "verifier-abc-123-xyz", scope)
	code := approveTxn(t, srv, txn)
	return clientID, exchangeCode(t, srv, clientID, code, "verifier-abc-123-xyz")
}

func mcpCall(t *testing.T, srv *httptest.Server, access, method string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":{"name":"ping","arguments":{}}}`))
	req.Header.Set("Content-Type", "application/json")
	if access != "" {
		req.Header.Set("Authorization", "Bearer "+access)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestFullOAuthFlowExecutesTool(t *testing.T) {
	_, srv := newTestLab(t)
	_, tok := fullFlow(t, srv, "mcp:tools offline_access")
	access := tok["access_token"].(string)
	if tok["refresh_token"] == "" {
		t.Fatal("offline_access scope must yield a refresh token")
	}
	code, body := mcpCall(t, srv, access, "tools/list")
	if code != http.StatusOK || !strings.Contains(body, `"ping"`) {
		t.Fatalf("tools/list: status=%d body=%s", code, body)
	}
	code, body = mcpCall(t, srv, access, "tools/call")
	if code != http.StatusOK || !strings.Contains(body, "pong") {
		t.Fatalf("tools/call: status=%d body=%s", code, body)
	}
}

func TestNoOfflineAccessNoRefresh(t *testing.T) {
	_, srv := newTestLab(t)
	_, tok := fullFlow(t, srv, "mcp:tools")
	if _, ok := tok["refresh_token"]; ok {
		t.Fatal("scope without offline_access must not yield a refresh token")
	}
}

func TestRegisterRejectsHTTPRedirect(t *testing.T) {
	_, srv := newTestLab(t)
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{"http://x.test/cb"}})
	resp, err := http.Post(srv.URL+"/oauth/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("http redirect: got %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeRejectsPlainPKCE(t *testing.T) {
	l, srv := newTestLab(t)
	l.mu.Lock()
	l.clients["cid-1"] = &clientRec{redirects: []string{testRedirect}}
	l.mu.Unlock()
	q := url.Values{
		"client_id": {"cid-1"}, "redirect_uri": {testRedirect},
		"response_type": {"code"}, "code_challenge": {"abc"},
		"code_challenge_method": {"plain"},
	}
	resp, err := http.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain PKCE: got %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeRejectsUnknownClient(t *testing.T) {
	_, srv := newTestLab(t)
	q := url.Values{
		"client_id": {"nope"}, "redirect_uri": {testRedirect},
		"response_type": {"code"}, "code_challenge": {"abc"},
		"code_challenge_method": {"S256"},
	}
	resp, err := http.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown client: got %d, want 400", resp.StatusCode)
	}
}

func TestCodeReplayDenied(t *testing.T) {
	_, srv := newTestLab(t)
	clientID := doRegister(t, srv, testRedirect)
	txn, _ := startAuthorize(t, srv, clientID, "verifier-replay-1", "mcp:tools")
	code := approveTxn(t, srv, txn)
	exchangeCode(t, srv, clientID, code, "verifier-replay-1")
	resp, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {"verifier-replay-1"}, "client_id": {clientID},
		"redirect_uri": {testRedirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("code replay: got %d, want 400", resp.StatusCode)
	}
}

func TestPKCEMismatchDenied(t *testing.T) {
	_, srv := newTestLab(t)
	clientID := doRegister(t, srv, testRedirect)
	txn, _ := startAuthorize(t, srv, clientID, "verifier-right", "mcp:tools")
	code := approveTxn(t, srv, txn)
	resp, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {"verifier-WRONG"}, "client_id": {clientID},
		"redirect_uri": {testRedirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PKCE mismatch: got %d, want 400", resp.StatusCode)
	}
}

func TestRedirectMismatchDenied(t *testing.T) {
	_, srv := newTestLab(t)
	clientID := doRegister(t, srv, testRedirect)
	txn, _ := startAuthorize(t, srv, clientID, "verifier-x", "mcp:tools")
	code := approveTxn(t, srv, txn)
	resp, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {"verifier-x"}, "client_id": {clientID},
		"redirect_uri": {"https://evil.test/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("redirect mismatch: got %d, want 400", resp.StatusCode)
	}
}

func TestConsentDenyYieldsNoCode(t *testing.T) {
	_, srv := newTestLab(t)
	clientID := doRegister(t, srv, testRedirect)
	txn, _ := startAuthorize(t, srv, clientID, "verifier-d", "mcp:tools")
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.PostForm(srv.URL+"/oauth/authorize", url.Values{
		"transaction_id": {txn}, "decision": {"deny"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error=access_denied") || strings.Contains(loc, "code=") {
		t.Fatalf("deny must redirect with access_denied and no code: %s", loc)
	}
	// Transaction is consumed: approving now must fail.
	resp2, err := noFollow.PostForm(srv.URL+"/oauth/authorize", url.Values{
		"transaction_id": {txn}, "decision": {"approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("consumed txn: got %d, want 400", resp2.StatusCode)
	}
}

func TestMCPRejectsBadTokens(t *testing.T) {
	l, srv := newTestLab(t)
	forge := func(aud, iss string, exp time.Time, scope string) string {
		tok, _, err := l.mintAccessCustom("cid-x", scope, aud, iss, exp)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	cases := map[string]string{
		"wrong audience": forge("https://evil.test/r/x/mcp", testIssuer, future, "mcp:tools"),
		"wrong issuer":   forge(testResource, "https://evil.test/", future, "mcp:tools"),
		"expired":        forge(testResource, testIssuer, past, "mcp:tools"),
		"missing scope":  forge(testResource, testIssuer, future, "other"),
		"malformed":      "not.a.jwt",
		"bad signature":  forge(testResource, testIssuer, future, "mcp:tools") + "x",
	}
	for name, tok := range cases {
		if code, _ := mcpCall(t, srv, tok, "tools/call"); code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", name, code)
		}
	}
	if code, _ := mcpCall(t, srv, "", "tools/call"); code != http.StatusUnauthorized {
		t.Errorf("missing bearer: got %d, want 401", code)
	}
}

func TestRevokedAccessDenied(t *testing.T) {
	_, srv := newTestLab(t)
	_, tok := fullFlow(t, srv, "mcp:tools offline_access")
	access := tok["access_token"].(string)
	if code, _ := mcpCall(t, srv, access, "tools/list"); code != http.StatusOK {
		t.Fatalf("pre-revoke call failed: %d", code)
	}
	resp, err := http.PostForm(srv.URL+"/oauth/revoke", url.Values{"token": {access}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if code, _ := mcpCall(t, srv, access, "tools/list"); code != http.StatusUnauthorized {
		t.Fatalf("post-revoke call: got %d, want 401", code)
	}
	// Refresh token revocation also sticks.
	rt := tok["refresh_token"].(string)
	resp2, err := http.PostForm(srv.URL+"/oauth/revoke", url.Values{"token": {rt}})
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	resp3, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoked refresh: got %d, want 400", resp3.StatusCode)
	}
}

func TestRefreshRotationInvalidatesOld(t *testing.T) {
	_, srv := newTestLab(t)
	_, tok := fullFlow(t, srv, "mcp:tools offline_access")
	rt := tok["refresh_token"].(string)
	resp, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["refresh_token"] == rt || out["refresh_token"] == "" {
		t.Fatal("refresh must rotate to a new token")
	}
	if code, _ := mcpCall(t, srv, out["access_token"].(string), "tools/call"); code != http.StatusOK {
		t.Fatalf("rotated access call: got %d, want 200", code)
	}
	resp2, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("old refresh reuse: got %d, want 400", resp2.StatusCode)
	}
}

func TestMetadataDocumentsAreCorrect(t *testing.T) {
	_, srv := newTestLab(t)
	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var prm struct {
		Resource string   `json:"resource"`
		AS       []string `json:"authorization_servers"`
	}
	_ = json.Unmarshal(raw, &prm)
	if prm.Resource != testResource {
		t.Fatalf("resource = %q, want %q", prm.Resource, testResource)
	}
	if len(prm.AS) != 1 || prm.AS[0] != testIssuer {
		t.Fatalf("authorization_servers = %v, want [%s]", prm.AS, testIssuer)
	}
	resp2, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	var asm struct {
		Issuer   string   `json:"issuer"`
		AuthURL  string   `json:"authorization_endpoint"`
		TokenURL string   `json:"token_endpoint"`
		RegURL   string   `json:"registration_endpoint"`
		S256     []string `json:"code_challenge_methods_supported"`
	}
	_ = json.Unmarshal(raw2, &asm)
	if asm.Issuer != testIssuer || asm.AuthURL != testIssuer+"/authorize" ||
		asm.TokenURL != testIssuer+"/token" || asm.RegURL != testIssuer+"/register" {
		t.Fatalf("AS metadata endpoints wrong: %+v", asm)
	}
	found := false
	for _, m := range asm.S256 {
		if m == "S256" {
			found = true
		}
	}
	if !found {
		t.Fatal("AS metadata must advertise S256")
	}
}
