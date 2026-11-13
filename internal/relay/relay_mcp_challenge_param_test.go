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
