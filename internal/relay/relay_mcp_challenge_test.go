package relay

// A: a managed MCP route must challenge like an RFC 6750 / RFC 9728
// resource. MCP SDK clients discover the Authorization Server from the
// WWW-Authenticate resource_metadata, so a bare 401 is an unusable endpoint:
// the client has no path to authorization.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ocliv/internal/authz"
)

// doManagedTool drives one request to the route's tool path through the
// public ingress and returns the recorder.
func doManagedTool(t *testing.T, s *Server, routeID, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/r/"+routeID+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Host = "public.example.org"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// A missing bearer must produce a 401 carrying the route-scoped RFC 9728
// resource metadata URL, so a standard client can start OAuth on its own.
func TestManagedRouteChallengesWithResourceMetadata(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-m", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-m", 1)
	route := publishRoute(t, s, priv, "key-test", "lse-m", "managed-oauth")
	_ = priv

	rec := doManagedTool(t, s, route, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-bearer status=%d, want 401", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	wantURI := "https://public.example.org/.well-known/oauth-protected-resource/r/" + route + "/mcp"
	if !strings.Contains(challenge, `resource_metadata="`+wantURI+`"`) {
		t.Fatalf("challenge %q missing route-scoped resource_metadata %q", challenge, wantURI)
	}
	if !strings.HasPrefix(challenge, "Bearer ") {
		t.Fatalf("challenge %q is not a Bearer challenge", challenge)
	}
	// A missing credential must NOT be described as an invalid token.
	if strings.Contains(challenge, "error=") {
		t.Fatalf("missing-bearer challenge carries an error code: %q", challenge)
	}
	// The challenge metadata URL must itself be served for this route.
	mreq := httptest.NewRequest(http.MethodGet, wantURI, nil)
	mreq.Host = "public.example.org"
	mrec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("challenge resource_metadata status=%d, want 200", mrec.Code)
	}
	if !strings.Contains(mrec.Body.String(), `"resource":"https://public.example.org/r/`+route+`/mcp"`) {
		t.Fatalf("PRM body not bound to this route: %s", mrec.Body.String())
	}
}

// A presented-but-invalid bearer is distinguished: 401 with
// error="invalid_token" and the same resource_metadata.
func TestManagedRouteInvalidBearerChallengeDistinguished(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-i", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-i", 1)
	route := publishRoute(t, s, priv, "key-test", "lse-i", "managed-oauth")
	_ = priv

	rec := doManagedTool(t, s, route, "not-a-real-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid-bearer status=%d, want 401", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Fatalf("invalid-bearer challenge lacks error=invalid_token: %q", challenge)
	}
	if !strings.Contains(challenge, `resource_metadata="https://public.example.org/.well-known/oauth-protected-resource/r/`+route+`/mcp"`) {
		t.Fatalf("invalid-bearer challenge lacks the route resource_metadata: %q", challenge)
	}
}

// A token minted for a DIFFERENT route must be rejected for this route:
// audience isolation holds per (tenant, route), and the challenge names
// this route's metadata.
func TestManagedRouteForeignAudienceRejected(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-a", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	insertMCPLeaseRow(t, db, "lse-b", "other.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-a", 1)
	liveFabricatedSession(t, s, "lse-b", 1)
	routeA := publishRoute(t, s, priv, "key-test", "lse-a", "managed-oauth")
	_ = priv
	routeB := publishRoute(t, s, priv, "key-test", "lse-b", "managed-oauth")

	az := authz.NewSQLStore(db.SQL())
	issuer, err := az.LoadIssuer()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := issuer.Mint(authz.TokenClaims{
		Issuer:   "https://public.example.org/r/" + routeB + "/oauth",
		Subject:  "cli-foreign",
		Audience: "https://public.example.org/r/" + routeB + "/mcp",
		Tenant:   "tenant-test",
		Route:    routeB,
		Expiry:   time.Now().Add(time.Hour).Unix(),
		ID:       "jti-foreign",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := doManagedTool(t, s, routeA, tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("foreign-audience token status=%d, want 401", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="https://public.example.org/.well-known/oauth-protected-resource/r/`+routeA+`/mcp"`) {
		t.Fatalf("challenge for the wrong route: %q", challenge)
	}
}
