package relay

// Priority 1 A, second pass: the WWW-Authenticate parameter NAME.
//
// RFC 9728 §5.1 defines the parameter that carries the protected
// resource metadata URL as `resource_metadata`, and the MCP 2025-11-25
// authorization spec requires servers to "include the resource metadata
// URL in the WWW-Authenticate HTTP header under `resource_metadata`".
//
// Ocliv emitted `resource_uri` instead. The official MCP SDK parses
// `resource_metadata` (mcp/client/auth/utils.py:
// `extract_field_from_www_auth(response, "resource_metadata")`), so it
// never saw the advertised URL and silently fell back to GUESSING the
// well-known path. The qualification passed only because the fallback
// happened to construct the same URL Ocliv serves.
//
// A client that trusts the challenge (and a client whose fallback
// differs, e.g. one that only tries the root well-known form) would
// dead-end. The challenge must name the parameter the RFC names, and
// the advertised URL must be the one the client is then required to
// fetch.
import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestManagedChallengeUsesRFC9728ResourceMetadataParameter pins the
// parameter NAME: `resource_metadata`, not `resource_uri`.
func TestManagedChallengeUsesRFC9728ResourceMetadataParameter(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-pm", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-pm", 1)
	route := publishRoute(t, s, priv, "key-test", "lse-pm", "managed-oauth")

	rec := doManagedTool(t, s, route, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-bearer status=%d, want 401", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	wantURI := "https://public.example.org/.well-known/oauth-protected-resource/r/" + route + "/mcp"
	if !strings.Contains(challenge, `resource_metadata="`+wantURI+`"`) {
		t.Fatalf("challenge %q does not carry the RFC 9728 parameter resource_metadata=%q",
			challenge, wantURI)
	}
	// The wrong parameter name must be gone: a client that scans for
	// resource_metadata must not be misled, and a client that scans for
	// resource_uri must not find a stale value.
	if strings.Contains(challenge, "resource_uri=") {
		t.Fatalf("challenge %q still carries the non-RFC resource_uri parameter", challenge)
	}
}

// TestManagedChallengeMetadataURLIsFetchableAndRouteBound proves the
// advertised URL is the exact document the client will be required to
// fetch, and that it is bound to THIS route (a challenge pointing at
// another route's metadata would let a client discover the wrong AS).
func TestManagedChallengeMetadataURLIsFetchableAndRouteBound(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-pb", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-pb", 1)
	route := publishRoute(t, s, priv, "key-test", "lse-pb", "managed-oauth")

	rec := doManagedTool(t, s, route, "")
	challenge := rec.Header().Get("WWW-Authenticate")
	start := strings.Index(challenge, `resource_metadata="`)
	if start < 0 {
		t.Fatalf("challenge %q has no resource_metadata parameter", challenge)
	}
	rest := challenge[start+len(`resource_metadata="`):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("challenge %q has an unterminated resource_metadata URL", challenge)
	}
	metadataURL := rest[:end]

	// The advertised URL must be served, and its resource must be THIS
	// route's tool endpoint.
	mreq := httptest.NewRequest(http.MethodGet, metadataURL, nil)
	mreq.Host = "public.example.org"
	mrec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("advertised metadata URL %q status=%d, want 200", metadataURL, mrec.Code)
	}
	if !strings.Contains(mrec.Body.String(), `"resource":"https://public.example.org/r/`+route+`/mcp"`) {
		t.Fatalf("advertised metadata is not bound to this route: %s", mrec.Body.String())
	}
	// The issuer it names must be this route's issuer.
	if !strings.Contains(mrec.Body.String(), `/r/`+route+`/oauth`) {
		t.Fatalf("advertised metadata does not name this route's issuer: %s", mrec.Body.String())
	}
}

// TestManagedChallengeMissingBearerHasNoErrorCodeAndInvalidDoes pins
// the missing-vs-invalid distinction the SDK relies on: a missing
// credential is not an "invalid token" error.
func TestManagedChallengeMissingBearerHasNoErrorCodeAndInvalidDoes(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-pd", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-pd", 1)
	route := publishRoute(t, s, priv, "key-test", "lse-pd", "managed-oauth")

	missing := doManagedTool(t, s, route, "")
	mc := missing.Header().Get("WWW-Authenticate")
	if strings.Contains(mc, "error=") {
		t.Fatalf("missing-bearer challenge carries an error code: %q", mc)
	}
	invalid := doManagedTool(t, s, route, "not-a-real-token")
	ic := invalid.Header().Get("WWW-Authenticate")
	if !strings.Contains(ic, `error="invalid_token"`) {
		t.Fatalf("invalid-bearer challenge lacks error=invalid_token: %q", ic)
	}
	if !strings.Contains(ic, `resource_metadata="`) {
		t.Fatalf("invalid-bearer challenge lost the metadata URL: %q", ic)
	}
}

// TestManagedDenialNeverRedirectsToUnlockPage pins the other half of
// Priority 1 A: an unauthorized MCP API request must be ANSWERED, not
// REDIRECTED. A 302 to the unlock page would send an API caller's
// FollowRedirects into POSTing its bearer to an HTML form, and would make
// a standards-shaped SDK report "too many redirects" instead of the 401
// that drives OAuth discovery.
//
// The relay's public path DOES redirect credential-less browser visits
// (relay_public.go: the visitor branch at the bottom of serveRouted).
// What this pins is that the MCP branch never reaches it: the managed
// authorization failure answers with the challenge directly.
func TestManagedDenialNeverRedirectsToUnlockPage(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-nr", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-nr", 1)
	route := publishRoute(t, s, priv, "key-test", "lse-nr", "managed-oauth")

	for _, tc := range []struct{ name, bearer string }{
		{"missing bearer", ""},
		{"invalid bearer", "not-a-real-token"},
	} {
		rec := doManagedTool(t, s, route, tc.bearer)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status=%d, want 401 (an MCP denial must not redirect)", tc.name, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("%s: carried a Location header %q - an API caller would be sent to an unlock page", tc.name, loc)
		}
		for _, sc := range []int{http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
			if rec.Code == sc {
				t.Fatalf("%s: status=%d is a redirect", tc.name, rec.Code)
			}
		}
		// It must still carry the challenge that starts discovery.
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `resource_metadata="`) {
			t.Fatalf("%s: lost the discovery challenge", tc.name)
		}
	}
}

// TestManagedRouteDiscoveryIsNotBehindAuthorization pins that the
// discovery document stays public even when the tool path is locked: a
// client must be able to follow the challenge without already holding a
// token (that is the whole point of the challenge).
func TestManagedRouteDiscoveryIsNotBehindAuthorization(t *testing.T) {
	s, db := newMCPServer(t)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	insertMCPLeaseRow(t, db, "lse-ds", "owner.t.example.test", AccessModeMCPManaged, "ACTIVE", 1, nil)
	liveFabricatedSession(t, s, "lse-ds", 1)
	route := publishRoute(t, s, priv, "key-test", "lse-ds", "managed-oauth")

	prm := "https://public.example.org/.well-known/oauth-protected-resource/r/" + route + "/mcp"
	req := httptest.NewRequest(http.MethodGet, prm, nil)
	req.Host = "public.example.org"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status=%d, want 200 (discovery must not require a token)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"resource":"https://public.example.org/r/`+route+`/mcp"`) {
		t.Fatalf("discovery not bound to this route: %s", rec.Body.String())
	}
	// And the AS metadata the PRM names is also public.
	as := "https://public.example.org/.well-known/oauth-authorization-server/r/" + route + "/oauth"
	areq := httptest.NewRequest(http.MethodGet, as, nil)
	areq.Host = "public.example.org"
	arec := httptest.NewRecorder()
	s.Handler().ServeHTTP(arec, areq)
	if arec.Code != http.StatusOK {
		t.Fatalf("AS metadata status=%d, want 200", arec.Code)
	}
	if !strings.Contains(arec.Body.String(), `"issuer":"https://public.example.org/r/`+route+`/oauth"`) {
		t.Fatalf("AS metadata issuer not bound to this route: %s", arec.Body.String())
	}
}
