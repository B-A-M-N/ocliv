package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
)

func seedEnrolledProfileForTest(t *testing.T, relayURL string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("OCLIV_CONFIG_DIR", filepath.Join(home, ".config", "ocliv"))
	t.Setenv("OCLIV_PROFILE", "")

	kp, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfgDir, err := config.DataDirForProfile("default")
	if err != nil {
		t.Fatalf("DataDirForProfile: %v", err)
	}
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := kp.Save(filepath.Join(cfgDir, "agent.key")); err != nil {
		t.Fatalf("Save key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, config.ConfigFile), []byte("relay_url = \""+relayURL+"\"\nkey_id = \"key-test\"\n"), 0o600); err != nil {
		t.Fatalf("Save config: %v", err)
	}
}

func TestMCPURLResolvesRelayOnlyPublicationAndFailsVerifyWhenOffline(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://relay.example")

	// Relay-only publication (no ServiceRecord in services.json).
	opsOK := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return 200, []byte(`{"publications":[{"route_id":"r-pub-only","pub_name":"pubonly","profile":"managed-oauth","url":"https://relay.example/r/r-pub-only/mcp","publication_state":"ACTIVE","desired_enabled":true,"session_live":true}]}`), nil
			}
			return 404, nil, nil
		},
	}
	if code := cmdMCPURLWithOps([]string{"pubonly"}, opsOK, func(string) error { return nil }, http.DefaultClient); code != apperr.ExitOK {
		t.Fatalf("relay-only lookup exit=%d, want 0", code)
	}

	// --copy failure must return nonzero.
	if code := cmdMCPURLWithOps([]string{"pubonly", "--copy"}, opsOK, func(string) error { return errors.New("no clipboard") }, http.DefaultClient); code == apperr.ExitOK {
		t.Fatal("expected nonzero exit when clipboard fails")
	}

	// Revoked publication must be refused.
	opsRevoked := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, []byte(`{"publications":[{"route_id":"r-rev","pub_name":"revsvc","profile":"managed-oauth","url":"https://relay.example/r/r-rev/mcp","publication_state":"REVOKED"}]}`), nil
		},
	}
	if code := cmdMCPURLWithOps([]string{"revsvc"}, opsRevoked, func(string) error { return nil }, http.DefaultClient); code == apperr.ExitOK {
		t.Fatal("expected nonzero exit for revoked publication")
	}

	// Cached URL with --verify when relay is unreachable must fail nonzero.
	dir, _ := config.DataDirForProfile("default")
	st := config.OpenServiceStore(dir)
	_ = st.Put(config.ServiceRecord{
		Name: "cachedsvc", Type: "mcp", Auth: "ocliv-managed", Profile: "default",
		RelayURL: "https://relay.example", PublicationID: "r-cached", PublicURL: "https://relay.example/r/r-cached/mcp",
	})
	opsDown := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 0, nil, errors.New("offline")
		},
	}
	if code := cmdMCPURLWithOps([]string{"cachedsvc", "--verify"}, opsDown, func(string) error { return nil }, http.DefaultClient); code == apperr.ExitOK {
		t.Fatal("expected nonzero exit for --verify when relay is unreachable")
	}
}

func TestMCPCheckValidatesDiscoveryMetadata(t *testing.T) {
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/r1/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/r/r1/mcp":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"` + srvURL + `/r/r1/mcp","authorization_servers":["` + srvURL + `/r/r1/oauth"]}`))
		case "/.well-known/oauth-authorization-server/r/r1/oauth":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + srvURL + `/r/r1/oauth","authorization_endpoint":"` + srvURL + `/r/r1/oauth/authorize","token_endpoint":"` + srvURL + `/r/r1/oauth/token","registration_endpoint":"` + srvURL + `/r/r1/oauth/register","code_challenge_methods_supported":["S256"]}`))
		case "/.well-known/google-connected-apps":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"connections":[{"app":"test"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	seedEnrolledProfileForTest(t, srvURL)
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, _, _ string) (int, []byte, error) {
			return 200, []byte(`{"publications":[{"route_id":"r1","pub_name":"kontrol","profile":"managed-oauth","url":"` + srvURL + `/r/r1/mcp","publication_state":"ACTIVE","desired_enabled":true}]}`), nil
		},
	}
	if code := cmdMCPCheckWithOps([]string{"kontrol", "--client", "chatgpt"}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("mcp check valid discovery exit=%d, want 0", code)
	}
	if code := cmdMCPCheckWithOps([]string{"kontrol", "--client", "google-connected-app"}, ops, srv.Client()); code != apperr.ExitOK {
		t.Fatalf("mcp check google-connected-app exit=%d, want 0", code)
	}
	if code := cmdMCPURLsWithOps([]string{"--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("mcp urls exit=%d, want 0", code)
	}
}

func TestDiscoveryEgressHardeningBlocksSSRF(t *testing.T) {
	// 1. Non-HTTPS, userinfo, and private/loopback/link-local IPs must be rejected.
	if res := runReadOnlyDiscoveryCheck(http.DefaultClient, "http://example.com/r/r1/mcp"); res.Transport != "FAIL" {
		t.Fatalf("expected http:// to fail, got %+v", res)
	}
	if res := runReadOnlyDiscoveryCheck(http.DefaultClient, "https://user:pass@example.com/r/r1/mcp"); res.Transport != "FAIL" {
		t.Fatalf("expected userinfo URL to fail, got %+v", res)
	}
	for _, addr := range []string{"127.0.0.1:443", "10.0.0.1:443", "169.254.169.254:443", "[::1]:443", "[fe80::1]:443"} {
		if _, err := safeEgressDialContext(context.Background(), "tcp", addr); err == nil || !strings.Contains(err.Error(), "egress policy") {
			t.Fatalf("expected egress policy block for %s, got %v", addr, err)
		}
	}

	// 2. Redirects and cross-origin authorization_servers must be rejected.
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/r1/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/r/r1/mcp":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"` + srvURL + `/r/r1/mcp","authorization_servers":["https://evil.example/r/r1/oauth"]}`))
		case "/r/redir/mcp":
			http.Redirect(w, r, srvURL+"/r/r1/mcp", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	if res := runReadOnlyDiscoveryCheck(srv.Client(), srvURL+"/r/r1/mcp"); res.Discovery != "FAIL" {
		t.Fatalf("expected cross-origin authorization_server to fail, got %+v", res)
	}
	if res := runReadOnlyDiscoveryCheck(srv.Client(), srvURL+"/r/redir/mcp"); res.Transport != "FAIL" {
		t.Fatalf("expected redirect during discovery to fail, got %+v", res)
	}
	_ = net.IPv4zero
}
