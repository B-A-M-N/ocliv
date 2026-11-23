package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func registerMulti(t *testing.T, s *Server, name string, redirects []string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"client_name":                name,
		"redirect_uris":              redirects,
		"token_endpoint_auth_method": "none",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(string(b)))
	s.ServeRegister(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.ClientID
}

func TestUnapprovedTrustedHostRedirectCannotBypassPairing(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	s := NewServer(issuer, st, "default", "r-auto", "https://relay.example/r/r-auto/mcp", "https://relay.example")
	s.AutoApproveRedirectHosts = []string{"chatgpt.com"}

	// Self-declared trusted-host redirect must NOT grant pairing-free access without explicit operator approval.
	clientID := registerMulti(t, s, "ChatGPT", []string{"https://chatgpt.com/connector_platform_oauth_redirect"})
	verifier := "v" + strings.Repeat("a", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/connector_platform_oauth_redirect") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=s1" +
		"&resource=" + url.QueryEscape(s.RouteURL)

	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, u, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("unapproved DCR client status=%d body=%s, want 200 consent form", w.Code, w.Body.String())
	}
	g, err := st.GetGrant(clientID, "default", "r-auto")
	if err != nil || g.Status != GrantPending || g.SkipPairing {
		t.Fatalf("grant=%+v err=%v, want pending + skip_pairing=false", g, err)
	}

	// Once explicitly operator-approved with ApproveGrantDirect, authorize succeeds in 0 clicks.
	if err := st.ApproveGrantDirect(clientID, "default", "r-auto"); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}
	w2 := httptest.NewRecorder()
	s.ServeAuthorize(w2, httptest.NewRequest(http.MethodGet, u, nil))
	if w2.Code != http.StatusFound {
		t.Fatalf("explicitly approved status=%d body=%s, want 302", w2.Code, w2.Body.String())
	}
	loc, err := url.Parse(w2.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("expected code in redirect, got %q (err=%v)", w2.Header().Get("Location"), err)
	}
}

func TestAutoApproveRejectsMixedRedirectURIs(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.AutoApproveRedirectHosts = []string{"chatgpt.com"}

	clientID := registerMulti(t, s, "Mixed", []string{
		"https://chatgpt.com/cb",
		"https://untrusted.example/cb",
	})
	if err := s.Store.ApproveGrantDirect(clientID, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}
	verifier := "v" + strings.Repeat("b", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/cb") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=s2" +
		"&resource=" + url.QueryEscape(s.RouteURL)

	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, u, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("mixed redirect URIs must fall through to consent form (200) when host allowlist is enforced, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestAutoApproveHTTPPublicRejectedAndLoopbackAllowed(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.AutoApproveRedirectHosts = []string{"example.com", "127.0.0.1"}

	pubClient := &Client{
		ID:           "cli_http_pub",
		RedirectURIs: []string{"http://example.com/cb"},
	}
	if s.canAutoApproveClient(pubClient) {
		t.Fatal("canAutoApproveClient allowed plain HTTP on non-loopback host")
	}

	loopID := registerMulti(t, s, "LocalCLI", []string{"http://127.0.0.1:54321/callback"})
	if err := s.Store.ApproveGrantDirect(loopID, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}
	verifier := "v" + strings.Repeat("c", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(loopID) +
		"&redirect_uri=" + url.QueryEscape("http://127.0.0.1:54321/callback") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=s3" +
		"&resource=" + url.QueryEscape(s.RouteURL)

	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, u, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("loopback status=%d body=%s, want 302", w.Code, w.Body.String())
	}
}

func TestAutoApproveNeverResurrectsRevokedGrant(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.AutoApproveRedirectHosts = []string{"chatgpt.com"}

	clientID := registerMulti(t, s, "ChatGPT", []string{"https://chatgpt.com/cb"})
	if err := s.Store.ApproveGrantDirect(clientID, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("ApproveGrantDirect: %v", err)
	}
	verifier := "v" + strings.Repeat("d", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/cb") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=s4" +
		"&resource=" + url.QueryEscape(s.RouteURL)

	w1 := httptest.NewRecorder()
	s.ServeAuthorize(w1, httptest.NewRequest(http.MethodGet, u, nil))
	if w1.Code != http.StatusFound {
		t.Fatalf("first authorize status=%d, want 302", w1.Code)
	}

	if err := s.Store.RevokeGrant(clientID, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	w2 := httptest.NewRecorder()
	s.ServeAuthorize(w2, httptest.NewRequest(http.MethodGet, u, nil))
	if w2.Code != http.StatusFound {
		t.Fatalf("revoked authorize status=%d body=%s, want 302 access_denied redirect", w2.Code, w2.Body.String())
	}
	loc2, _ := url.Parse(w2.Header().Get("Location"))
	if loc2.Query().Get("error") != "access_denied" || loc2.Query().Get("code") != "" || loc2.Query().Get("iss") != s.IssuerURL {
		t.Fatalf("revoked authorize redirect=%q, want error=access_denied with iss and no code", loc2.String())
	}
	g, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil || g.Status != GrantRevoked {
		t.Fatalf("grant=%+v err=%v, want revoked", g, err)
	}
}
