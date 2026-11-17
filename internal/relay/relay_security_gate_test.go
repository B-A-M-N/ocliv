package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"ocliv/internal/authz"
	"ocliv/internal/lease"
)

func TestOuterHostGateAdmitsAppendedASMetadata(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "alpha.t.example.test", AccessModeMCPManaged, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "managed-oauth")

	for _, p := range []string{
		"/.well-known/oauth-authorization-server/r/" + r1 + "/oauth",
		"/r/" + r1 + "/oauth/.well-known/oauth-authorization-server",
		"/r/" + r1 + "/oauth/.well-known/openid-configuration",
	} {
		req := httptest.NewRequest(http.MethodGet, "https://"+s.mcpHost+p, nil)
		req.Host = s.mcpHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code == http.StatusMisdirectedRequest || w.Code == http.StatusNotFound {
			t.Fatalf("GET %s blocked at outer Host gate: status=%d body=%s", p, w.Code, w.Body.String())
		}
	}
}

func TestUnsignedDirectQueryCannotBypassPairingAndTamperedPathRejected(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "alpha.t.example.test", AccessModeMCPManaged, lease.StateActive, 1, nil)
	r1 := publishRoute(t, s, priv, "key-test", "lse-a", "managed-oauth")

	st := authz.NewSQLStore(db.SQL())
	if err := st.RegisterClient(authz.Client{
		ID: "cli_1", Name: "C1", RedirectURIs: []string{"https://client.example/cb"},
		Tenant: "tenant-test", Route: r1,
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	// 1. Signed ordinary /authz/approve/cli_1 with unsigned ?direct=1 MUST NOT set skip_pairing.
	ordPath := "/v1/agent/mcp-routes/" + r1 + "/authz/approve/cli_1"
	reqOrd := signedMgmtRequest(t, priv, "key-test", http.MethodPost, ordPath)
	reqOrd.Host = s.relayHost
	reqOrd.URL.RawQuery = "direct=1"
	reqOrd.RequestURI = ordPath + "?direct=1"
	wOrd := httptest.NewRecorder()
	s.Handler().ServeHTTP(wOrd, reqOrd)
	if wOrd.Code != http.StatusOK {
		t.Fatalf("ordinary approve status=%d body=%s", wOrd.Code, wOrd.Body.String())
	}
	g, err := st.GetGrant("cli_1", "tenant-test", r1)
	if err != nil || g.SkipPairing {
		t.Fatalf("unsigned ?direct=1 set SkipPairing=true! grant=%+v", g)
	}

	// 2. Replaying ordinary signature against /authz/approve-direct/cli_1 MUST be denied (403).
	tamperPath := "/v1/agent/mcp-routes/" + r1 + "/authz/approve-direct/cli_1"
	reqTamper := signedMgmtRequest(t, priv, "key-test", http.MethodPost, ordPath)
	reqTamper.Host = s.relayHost
	reqTamper.URL.Path = tamperPath
	reqTamper.RequestURI = tamperPath
	wTamper := httptest.NewRecorder()
	s.Handler().ServeHTTP(wTamper, reqTamper)
	if wTamper.Code != http.StatusForbidden {
		t.Fatalf("tampered path status=%d, want 403", wTamper.Code)
	}

	// 3. Properly signed /authz/approve-direct/cli_1 activates SkipPairing=true.
	reqDirect := signedMgmtRequest(t, priv, "key-test", http.MethodPost, tamperPath)
	reqDirect.Host = s.relayHost
	wDirect := httptest.NewRecorder()
	s.Handler().ServeHTTP(wDirect, reqDirect)
	if wDirect.Code != http.StatusOK {
		t.Fatalf("direct approve status=%d body=%s", wDirect.Code, wDirect.Body.String())
	}
	g2, err := st.GetGrant("cli_1", "tenant-test", r1)
	if err != nil || !g2.SkipPairing {
		t.Fatalf("expected SkipPairing=true after signed approve-direct, got %+v", g2)
	}
}

func TestCORSPreflightAllowsModernMCPHeaders(t *testing.T) {
	s, _ := newMCPServer(t)
	req := httptest.NewRequest(http.MethodOptions, "https://"+s.mcpHost+"/r/any/mcp", nil)
	req.Host = s.mcpHost
	req.Header.Set("Origin", "https://chatgpt.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type, Mcp-Method, Mcp-Name")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status=%d, want 204", w.Code)
	}
	allow := w.Header().Get("Access-Control-Allow-Headers")
	for _, want := range []string{"Mcp-Method", "Mcp-Name", "Mcp-Session-Id", "Mcp-Protocol-Version"} {
		if !containsFold(allow, want) {
			t.Fatalf("Access-Control-Allow-Headers=%q missing %q", allow, want)
		}
	}
	if w.Header().Get("Vary") == "" {
		t.Fatal("expected Vary header on CORS preflight response")
	}
}

func TestGoogleDomainVerificationEndpoint(t *testing.T) {
	s, _ := newMCPServer(t)
	s.googleVerificationJSON = []byte(`{"verification_token":"tok-123"}`)

	// Exact host + exact path -> 200 JSON, no redirect.
	reqOK := httptest.NewRequest(http.MethodGet, "https://"+s.mcpHost+"/.well-known/google-connected-apps", nil)
	reqOK.Host = s.mcpHost
	wOK := httptest.NewRecorder()
	s.Handler().ServeHTTP(wOK, reqOK)
	if wOK.Code != http.StatusOK || wOK.Body.String() != `{"verification_token":"tok-123"}` {
		t.Fatalf("google verification status=%d body=%q", wOK.Code, wOK.Body.String())
	}

	// Unrelated .well-known path must NOT be admitted as a wildcard bypass.
	reqOther := httptest.NewRequest(http.MethodGet, "https://"+s.mcpHost+"/.well-known/security.txt", nil)
	reqOther.Host = s.mcpHost
	wOther := httptest.NewRecorder()
	s.Handler().ServeHTTP(wOther, reqOther)
	if wOther.Code == http.StatusOK {
		t.Fatalf("unexpected 200 on /.well-known/security.txt")
	}

	// Wrong host must be rejected with 421.
	reqBadHost := httptest.NewRequest(http.MethodGet, "https://"+s.relayHost+"/.well-known/google-connected-apps", nil)
	reqBadHost.Host = s.relayHost
	wBadHost := httptest.NewRecorder()
	s.Handler().ServeHTTP(wBadHost, reqBadHost)
	if wBadHost.Code != http.StatusMisdirectedRequest {
		t.Fatalf("wrong host status=%d, want 421", wBadHost.Code)
	}
}

func containsFold(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				match := true
				for j := 0; j < len(needle); j++ {
					a, b := haystack[i+j], needle[j]
					if a >= 'A' && a <= 'Z' {
						a += 'a' - 'A'
					}
					if b >= 'A' && b <= 'Z' {
						b += 'a' - 'A'
					}
					if a != b {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
			return false
		})())
}
