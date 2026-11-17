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

func TestAutoApproveAllowlistedHTTPSHost(t *testing.T) {
	db := openTestDB(t)
	applySchema(t, db)
	st := NewSQLStore(db)
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	s := NewServer(issuer, st, "default", "r-auto", "https://relay.example/r/r-auto/mcp", "https://relay.example")
	s.AutoApproveRedirectHosts = []string{"chatgpt.com"}

	clientID := registerMulti(t, s, "ChatGPT", []string{"https://chatgpt.com/connector_platform_oauth_redirect"})
	verifier := "v" + strings.Repeat("a", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/connector_platform_oauth_redirect") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=s1" +
		"&resource=" + url.QueryEscape(s.RouteURL)

	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, u, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s, want 302", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("expected code in redirect, got %q (err=%v)", w.Header().Get("Location"), err)
	}
	g, err := st.GetGrant(clientID, "default", "r-auto")
	if err != nil || g.Status != GrantActive || !g.SkipPairing {
		t.Fatalf("grant=%+v err=%v, want active + skip_pairing", g, err)
	}
	var auditCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM authz_audit WHERE action='auto-approve' AND client_id=? AND result='ok'`, clientID).Scan(&auditCount); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("auditCount=%d, want 1", auditCount)
	}
}

func TestAutoApproveRejectsMixedRedirectURIs(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.AutoApproveRedirectHosts = []string{"chatgpt.com"}

	clientID := registerMulti(t, s, "Mixed", []string{
		"https://chatgpt.com/cb",
		"https://untrusted.example/cb",
	})
	verifier := "v" + strings.Repeat("b", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/cb") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=s2" +
		"&resource=" + url.QueryEscape(s.RouteURL)

	w := httptest.NewRecorder()
	s.ServeAuthorize(w, httptest.NewRequest(http.MethodGet, u, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("mixed redirect URIs must fall through to consent form (200), got %d body=%s", w.Code, w.Body.String())
	}
	g, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil || g.Status != GrantPending || g.SkipPairing {
		t.Fatalf("grant=%+v err=%v, want pending without skip_pairing", g, err)
	}
}

func TestAutoApproveHTTPPublicRejectedAndLoopbackAllowed(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.AutoApproveRedirectHosts = []string{"example.com", "127.0.0.1"}

	// Plain HTTP on non-loopback host is rejected by ValidateRedirectURI / canAutoApproveClient.
	pubClient := &Client{
		ID:           "cli_http_pub",
		RedirectURIs: []string{"http://example.com/cb"},
	}
	if s.canAutoApproveClient(pubClient) {
		t.Fatal("canAutoApproveClient allowed plain HTTP on non-loopback host")
	}

	// Loopback HTTP with port on allowlisted 127.0.0.1 succeeds.
	loopID := registerMulti(t, s, "LocalCLI", []string{"http://127.0.0.1:54321/callback"})
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
	verifier := "v" + strings.Repeat("d", 42)
	u := "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/cb") +
		"&code_challenge=" + url.QueryEscape(CodeChallengeS256(verifier)) +
		"&code_challenge_method=S256&state=s4" +
		"&resource=" + url.QueryEscape(s.RouteURL)

	// First request auto-approves.
	w1 := httptest.NewRecorder()
	s.ServeAuthorize(w1, httptest.NewRequest(http.MethodGet, u, nil))
	if w1.Code != http.StatusFound {
		t.Fatalf("first authorize status=%d, want 302", w1.Code)
	}

	// Revoke the grant.
	if err := s.Store.RevokeGrant(clientID, s.tenant(), s.RouteID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	// Subsequent request must be denied and never resurrected.
	w2 := httptest.NewRecorder()
	s.ServeAuthorize(w2, httptest.NewRequest(http.MethodGet, u, nil))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("revoked authorize status=%d body=%s, want 400", w2.Code, w2.Body.String())
	}
	g, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil || g.Status != GrantRevoked {
		t.Fatalf("grant=%+v err=%v, want revoked", g, err)
	}
}
