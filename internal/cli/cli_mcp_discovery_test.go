package cli

// Publish-time OAuth discovery validation tests (P0-E). After route
// registration the publisher must prove the upstream's advertised
// protected-resource metadata names exactly the published route URL.
// A mismatch fails closed; an unreachable discovery endpoint is
// inconclusive (warn, do not publish blindly nor block on publisher
// network position).

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"ocliv/internal/config"
)

func TestMCPRouteDiscoveryURL(t *testing.T) {
	got, err := mcpRouteDiscoveryURL("https://public.example.org/r/abc123/mcp", "abc123")
	if err != nil || got != "https://public.example.org/.well-known/oauth-protected-resource/r/abc123/mcp" {
		t.Fatalf("derivation = (%q, %v)", got, err)
	}
	for name, pair := range map[string][2]string{
		"non-https":  {"http://public.example.org/r/abc123/mcp", "abc123"},
		"wrong id":   {"https://public.example.org/r/other/mcp", "abc123"},
		"wrong path": {"https://public.example.org/r/abc123/other", "abc123"},
		"no host":    {"https:///r/abc123/mcp", "abc123"},
	} {
		if _, err := mcpRouteDiscoveryURL(pair[0], pair[1]); err == nil {
			t.Errorf("%s: malformed route URL accepted", name)
		}
	}
}

func TestValidateMCPResourceMetadata(t *testing.T) {
	client := &http.Client{}
	// Match: nil.
	match := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/.well-known/oauth-protected-resource/mcp" {
			t.Errorf("upstream saw path %q", r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"https://public.example.org/r/abc/mcp","authorization_servers":["https://idp.example"]}`))
	}))
	defer match.Close()
	if err := validateMCPResourceMetadata(client, match.URL+"/.well-known/oauth-protected-resource/mcp", "https://public.example.org/r/abc/mcp"); err != nil {
		t.Fatalf("matching metadata rejected: %v", err)
	}
	// Mismatch: hard error, never unreachable.
	mismatch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"https://evil.example/r/abc/mcp"}`))
	}))
	defer mismatch.Close()
	err := validateMCPResourceMetadata(client, mismatch.URL+"/.well-known/oauth-protected-resource/mcp", "https://public.example.org/r/abc/mcp")
	if err == nil || errors.Is(err, errDiscoveryUnreachable) {
		t.Fatalf("mismatched resource = %v, want fail-closed mismatch", err)
	}
	// Missing document: fail closed, not silent.
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer missing.Close()
	if err := validateMCPResourceMetadata(client, missing.URL+"/.well-known/oauth-protected-resource/mcp", "https://public.example.org/r/abc/mcp"); err == nil ||
		errors.Is(err, errDiscoveryUnreachable) {
		t.Fatalf("absent discovery = %v, want fail-closed error", err)
	}
	// Unreachable: inconclusive, distinctly reported.
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := closed.URL
	closed.Close()
	if err := validateMCPResourceMetadata(client, url, "https://public.example.org/r/abc/mcp"); !errors.Is(err, errDiscoveryUnreachable) {
		t.Fatalf("unreachable discovery = %v, want errDiscoveryUnreachable", err)
	}
}

// TestDoctorLoopbackTargetHonorsFamily: the doctor must probe the exact
// loopback family the tunnel was started with. An IPv6-only server must
// not be diagnosed via 127.0.0.1 (possibly a different service on the
// same port); an unknown record keeps the historical IPv4 default.
func TestDoctorLoopbackTargetHonorsFamily(t *testing.T) {
	dir := t.TempDir()
	store, err := config.OpenLeaseStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(config.LeaseRecord{LeaseID: "lse-v6", Port: 8765, IPv6: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(config.LeaseRecord{LeaseID: "lse-v4", Port: 8765}); err != nil {
		t.Fatal(err)
	}
	if got := doctorLoopbackTarget(dir, "lse-v6", 8765); got != "[::1]:8765" {
		t.Fatalf("v6 lease target = %q, want [::1]:8765", got)
	}
	if got := doctorLoopbackTarget(dir, "lse-v4", 8765); got != "127.0.0.1:8765" {
		t.Fatalf("v4 lease target = %q, want 127.0.0.1:8765", got)
	}
	if got := doctorLoopbackTarget(dir, "lse-missing", 8765); got != "127.0.0.1:8765" {
		t.Fatalf("unknown lease target = %q, want 127.0.0.1:8765 default", got)
	}
}
