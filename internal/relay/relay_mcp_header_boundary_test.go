package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/access"
)

// TestMCPUpstreamOAuthHeaderBoundary proves the header boundary on the
// real relay path (serveProxied -> proxy.SanitizeVisitorHeaders ->
// protocol.WriteFrame over a real yamux session, captured by the fake
// agent end). For an upstream-oauth MCP lease:
//
//  1. the client's application Authorization header is forwarded to the
//     upstream byte-identical (the upstream resource server owns
//     issuer/audience/scope/expiry/revocation validation — the relay
//     performs no OAuth itself, and Ocliv visitor credentials are
//     neither demanded nor consulted, P0-B);
//  2. Ocliv's own visitor credential header (X-Ocliv-Authorization,
//     access.HeaderName) is STRIPPED and never reaches the upstream;
//  3. hop-by-hop and spoofed forwarded headers are stripped, while a
//     legit application header survives.
func TestMCPUpstreamOAuthHeaderBoundary(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = db
	const leaseID = "lse-hdr"
	insertLeaseRow(t, db, leaseID, "ACTIVE", 1, nil)
	h := newDispatchHarness(t)
	sess := &Session{LeaseID: leaseID, Generation: 1, Yamux: h.relayYS,
		Budget: s.budgets.For(leaseID), closed: make(chan struct{})}
	insertRegistrySession(s, sess)

	tgt := &routeTarget{LeaseID: leaseID, Generation: 1,
		AccessMode: AccessModeMCPUpstreamOAuth, Hostname: "h-" + leaseID + ".t.example.test",
		MCPProfile: IngressMCPUpstreamOAuth, MCPVerified: true, ViaPathRoute: true}

	// A synthetic-but-wire-shaped application credential. The relay must
	// treat it as opaque bytes and forward them unchanged; nothing here
	// validates the JWT.
	const jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImV4YW1wbGUifQ.eyJpc3MiOiJodHRwczovL2lkcC50ZXN0L3JlYWxtIn0.SIG-signature-bytes"
	req := httptest.NewRequest(http.MethodPost, "http://h-"+leaseID+".t.example.test/mcp", nil)
	req.RequestURI = "/mcp"
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set(access.HeaderName, "secret-ocliv-visitor-credential") // Ocliv's own credential
	req.Header.Set("X-Custom-App", "keep-me")
	req.Header.Set("X-Forwarded-For", "6.6.6.6") // spoofed: must be stripped
	req.Header.Set("Connection", "keep-alive")   // hop-by-hop: must be stripped
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { defer close(done); s.serveProxied(rec, req, tgt, sess, false, false) }()

	select {
	case head := <-h.gotHead:
		want := "Bearer " + jwt
		if got := head.Headers["Authorization"]; got != want {
			t.Fatalf("forwarded Authorization = %q, want %q (byte-identical client credential)", got, want)
		}
		if _, leaked := head.Headers[access.HeaderName]; leaked {
			t.Fatalf("Ocliv visitor credential leaked upstream: %s present in the wire head", access.HeaderName)
		}
		if v, ok := head.Headers["X-Forwarded-For"]; ok {
			t.Fatalf("spoofed forwarded header leaked upstream: %q", v)
		}
		if v, ok := head.Headers["Connection"]; ok {
			t.Fatalf("hop-by-hop Connection leaked upstream: %q", v)
		}
		if got := head.Headers["X-Custom-App"]; got != "keep-me" {
			t.Fatalf("legit application header dropped: got %q", got)
		}
		if head.Method != "POST" || head.Path != "/mcp" {
			t.Fatalf("wire head method/path = %s %s, want POST /mcp", head.Method, head.Path)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("no request head reached the wire")
	}
	<-done
}

// TestManagedOAuthHeaderInjectionAfterSanitization (2026-11-14 review P2):
// externally supplied X-Ocliv-Upstream-Sub / X-Ocliv-Route are reserved
// relay metadata names and must not survive sanitization on ANY ingress
// mode. On a managed route the relay injects its own verified values
// AFTER sanitization, so an attacker's spoofed header cannot reach the
// upstream and a legitimate managed identity is preserved.
func TestManagedOAuthHeaderInjectionAfterSanitization(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = db
	const leaseID = "lse-hdr-mgd"
	insertLeaseRow(t, db, leaseID, "ACTIVE", 1, nil)
	h := newDispatchHarness(t)
	sess := &Session{LeaseID: leaseID, Generation: 1, Yamux: h.relayYS,
		Budget: s.budgets.For(leaseID), closed: make(chan struct{})}
	insertRegistrySession(s, sess)

	tgt := &routeTarget{LeaseID: leaseID, Generation: 1,
		AccessMode: AccessModeMCPManaged, Hostname: "h-" + leaseID + ".t.example.test",
		MCPProfile: IngressMCPManaged, MCPVerified: true, ViaPathRoute: true,
		TenantID: "tenant-test", RouteID: "rt-" + leaseID}

	req := httptest.NewRequest(http.MethodPost, "http://h-"+leaseID+".t.example.test/mcp", nil)
	req.RequestURI = "/mcp"
	// Spoofed relay identity metadata from the visitor side.
	req.Header.Set("X-Ocliv-Upstream-Sub", "spoofed-subject")
	req.Header.Set("X-Ocliv-Route", "spoofed-route")
	req.Header.Set("Authorization", "Bearer attacker-bearer")
	// The managed path strips the external bearer before forwarding (the
	// real serveRouted does this after authorizeManaged succeeds).
	req.Header.Del("Authorization")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	// The managed path passes the relay-verified subject (the real
	// serveRouted call does this after authorizeManaged succeeds).
	go func() {
		defer close(done)
		s.serveProxied(rec, req, tgt, sess, false, false, "verified-client-subject")
	}()

	select {
	case head := <-h.gotHead:
		if got := head.Headers["X-Ocliv-Upstream-Sub"]; got != "verified-client-subject" {
			t.Fatalf("managed identity not injected after sanitization: %q (want the verified subject)", got)
		}
		if got := head.Headers["X-Ocliv-Route"]; got == "spoofed-route" || got == "" {
			t.Fatalf("managed route metadata not injected after sanitization: %q (want the route id)", got)
		}
		if _, leaked := head.Headers["Authorization"]; leaked {
			t.Fatal("external bearer leaked upstream on a managed route")
		}
	case <-time.After(12 * time.Second):
		t.Fatal("no request head reached the wire")
	}
	<-done
}

// TestNativeOAuthHeaderSpoofStripped (2026-11-14 review P2): on the
// upstream-oauth profile the spoofed relay identity headers must be
// stripped by the sanitizer, and the application Authorization header is
// preserved byte-identically.
func TestNativeOAuthHeaderSpoofStripped(t *testing.T) {
	s, db := newLifecycleServer(t)
	_ = db
	const leaseID = "lse-hdr-native"
	insertLeaseRow(t, db, leaseID, "ACTIVE", 1, nil)
	h := newDispatchHarness(t)
	sess := &Session{LeaseID: leaseID, Generation: 1, Yamux: h.relayYS,
		Budget: s.budgets.For(leaseID), closed: make(chan struct{})}
	insertRegistrySession(s, sess)

	tgt := &routeTarget{LeaseID: leaseID, Generation: 1,
		AccessMode: AccessModeMCPUpstreamOAuth, Hostname: "h-" + leaseID + ".t.example.test",
		MCPProfile: IngressMCPUpstreamOAuth, MCPVerified: true, ViaPathRoute: true}

	req := httptest.NewRequest(http.MethodPost, "http://h-"+leaseID+".t.example.test/mcp", nil)
	req.RequestURI = "/mcp"
	req.Header.Set("X-Ocliv-Upstream-Sub", "spoofed-subject")
	req.Header.Set("X-Ocliv-Route", "spoofed-route")
	req.Header.Set("Authorization", "Bearer app-credential")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { defer close(done); s.serveProxied(rec, req, tgt, sess, false, false) }()

	select {
	case head := <-h.gotHead:
		if _, leaked := head.Headers["X-Ocliv-Upstream-Sub"]; leaked {
			t.Fatal("spoofed X-Ocliv-Upstream-Sub survived sanitization on the native-oauth profile")
		}
		if _, leaked := head.Headers["X-Ocliv-Route"]; leaked {
			t.Fatal("spoofed X-Ocliv-Route survived sanitization on the native-oauth profile")
		}
		if got := head.Headers["Authorization"]; got != "Bearer app-credential" {
			t.Fatalf("application Authorization corrupted: %q", got)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("no request head reached the wire")
	}
	<-done
}
