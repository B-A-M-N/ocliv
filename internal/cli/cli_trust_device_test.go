package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func setupTestProfileWithService(t *testing.T, svcName, routeID string) (string, *identity.KeyPair, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("OCLIV_PROFILE", "default")

	cfgDir, keyPath, cfgPath, err := agentFilesForProfile("default")
	if err != nil {
		t.Fatalf("agentFilesForProfile: %v", err)
	}
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	k, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := k.Save(keyPath); err != nil {
		t.Fatalf("Save key: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte("relay_url = \"https://relay.example\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	st, err := openServicesForProfile("default")
	if err != nil {
		t.Fatalf("openServices: %v", err)
	}
	if err := st.Put(config.ServiceRecord{
		Name:          svcName,
		Type:          "mcp",
		BackendMode:   config.BackendAttached,
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		Profile:       "default",
		RelayURL:      "https://relay.example",
		PublicationID: routeID,
		PublicURL:     "https://relay.example/r/" + routeID + "/mcp",
	}); err != nil {
		t.Fatalf("Upsert service: %v", err)
	}
	return home, k, "key-" + string(k.ID())
}

func TestCLITrustUntrustAndRevokeClient(t *testing.T) {
	_, _, _ = setupTestProfileWithService(t, "tools", "AbCdEfGhIjKlMnOpQrStUv")

	var lastMethod, lastPath string
	var lastBody []byte
	ops := serviceOps{
		mgmtCall: func(relayURL string, k *identity.KeyPair, keyID, method, path string) (int, []byte, error) {
			lastMethod, lastPath = method, path
			switch {
			case method == http.MethodPost && strings.Contains(path, "/authz/approve-direct/"):
				return http.StatusOK, []byte(`{"client_id":"cli_123","direct":true,"status":"approved"}`), nil
			case method == http.MethodDelete && strings.Contains(path, "/trust/"):
				return http.StatusOK, []byte(`{"status":"revoked","revoked":1}`), nil
			case method == http.MethodPost && strings.Contains(path, "/authz/revoke/"):
				return http.StatusOK, []byte(`{"status":"revoked"}`), nil
			default:
				return http.StatusNotFound, []byte("not found"), nil
			}
		},
		mgmtCallBody: func(relayURL string, k *identity.KeyPair, keyID, method, path string, reqBody []byte) (int, []byte, error) {
			lastMethod, lastPath, lastBody = method, path, reqBody
			pol := authz.ClientTrustPolicy{
				ID:           "tp_test",
				Kind:         "chatgpt",
				RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
				Enabled:      true,
			}
			b, _ := json.Marshal(map[string]any{"status": "created", "policy": pol})
			return http.StatusCreated, b, nil
		},
	}

	// 1. `ocliv trust tools chatgpt`
	if code := cmdTrustWithOps([]string{"tools", "chatgpt"}, ops); code != apperr.ExitOK {
		t.Fatalf("cmdTrust chatgpt exit=%d, want 0", code)
	}
	if lastMethod != http.MethodPost || lastPath != "/v1/agent/mcp-routes/AbCdEfGhIjKlMnOpQrStUv/trust" {
		t.Fatalf("unexpected trust call: %s %s", lastMethod, lastPath)
	}
	if !strings.Contains(string(lastBody), `"chatgpt"`) {
		t.Fatalf("unexpected trust body: %s", string(lastBody))
	}

	// 2. HTTP redirect URI is rejected locally before hitting relay.
	if code := cmdTrustWithOps([]string{"tools", "--redirect-uri", "http://evil.example/cb"}, ops); code != apperr.ExitCLIValidation {
		t.Fatalf("HTTP redirect-uri exit=%d, want validation error", code)
	}

	// 3. `ocliv trust tools --client cli_123`
	if code := cmdTrustWithOps([]string{"tools", "--client", "cli_123"}, ops); code != apperr.ExitOK {
		t.Fatalf("cmdTrust --client exit=%d, want 0", code)
	}
	if lastMethod != http.MethodPost || lastPath != "/v1/agent/mcp-routes/AbCdEfGhIjKlMnOpQrStUv/authz/approve-direct/cli_123" {
		t.Fatalf("unexpected approve-direct call: %s %s", lastMethod, lastPath)
	}

	// 4. `ocliv untrust tools chatgpt`
	if code := cmdUntrustWithOps([]string{"tools", "chatgpt"}, ops); code != apperr.ExitOK {
		t.Fatalf("cmdUntrust exit=%d, want 0", code)
	}
	if lastMethod != http.MethodDelete || lastPath != "/v1/agent/mcp-routes/AbCdEfGhIjKlMnOpQrStUv/trust/chatgpt" {
		t.Fatalf("unexpected untrust call: %s %s", lastMethod, lastPath)
	}

	// 5. `ocliv revoke client cli_123` (auto-resolves single MCP service `tools`).
	if code := cmdRevokeWithOps([]string{"client", "cli_123"}, ops); code != apperr.ExitOK {
		t.Fatalf("cmdRevoke client exit=%d, want 0", code)
	}
	if lastMethod != http.MethodPost || lastPath != "/v1/agent/mcp-routes/AbCdEfGhIjKlMnOpQrStUv/authz/revoke/cli_123" {
		t.Fatalf("unexpected revoke call: %s %s", lastMethod, lastPath)
	}
}

func TestHostTrustFlagValidation(t *testing.T) {
	// Unknown preset rejected immediately.
	if code := cmdHostWithOps([]string{"mcp", "8765", "--name", "tools", "--trust", "unknown-client"}, defaultServiceOps()); code != apperr.ExitCLIValidation {
		t.Fatalf("unknown --trust preset exit=%d, want ExitCLIValidation", code)
	}
	// --trust on http service rejected immediately.
	if code := cmdHostWithOps([]string{"http", "3000", "--name", "web", "--trust", "chatgpt"}, defaultServiceOps()); code != apperr.ExitCLIValidation {
		t.Fatalf("--trust on http service exit=%d, want ExitCLIValidation", code)
	}
}

func TestDeviceAddValidation(t *testing.T) {
	if code := cmdDevice([]string{"add"}); code != apperr.ExitCLIValidation {
		t.Fatalf("device add with no args exit=%d, want ExitCLIValidation", code)
	}
	if code := cmdDevice([]string{"add", "user@host", "--local-user", "alice", "--relay", "https://relay.example"}); code != apperr.ExitCLIValidation {
		t.Fatalf("device add with both target and --local-user exit=%d, want ExitCLIValidation", code)
	}
	if code := cmdDevice([]string{"add", "--local-user", "-baduser", "--relay", "https://relay.example"}); code != apperr.ExitCLIValidation {
		t.Fatalf("device add with invalid local-user exit=%d, want ExitCLIValidation", code)
	}
	for _, badProfile := range []string{"-lead", "a;id", "a&&id", "$(id)", "`id`", "a'b", `a"b`, "a b"} {
		if validProfileName(badProfile) {
			t.Fatalf("validProfileName(%q) = true, want false", badProfile)
		}
		if code := cmdDevice([]string{"add", "user@host", "--relay", "https://relay.example", "--profile", badProfile}); code != apperr.ExitCLIValidation {
			t.Fatalf("device add with bad profile %q exit=%d, want ExitCLIValidation", badProfile, code)
		}
	}
	for _, goodProfile := range []string{"default", "prod-1", "stage_2.0"} {
		if !validProfileName(goodProfile) {
			t.Fatalf("validProfileName(%q) = false, want true", goodProfile)
		}
	}
}

func TestSSHCommandQuotingPreservesLiteralArguments(t *testing.T) {
	adversarial := []string{
		"https://relay.example;touch /tmp/pwned",
		"https://relay.example&&id",
		"https://relay.example/$(id)",
		"https://relay.example/`id`",
		"https://relay.example/a'b\"c",
	}
	for _, payload := range adversarial {
		// Execute the quoted command string via /bin/sh with printf to verify
		// POSIX shell treats every adversarial byte as a single literal argument.
		cmdStr := buildSSHCommandString("printf", "%s", payload)
		out, err := exec.Command("/bin/sh", "-c", cmdStr).Output()
		if err != nil {
			t.Fatalf("sh -c %q failed: %v", cmdStr, err)
		}
		if string(out) != payload {
			t.Fatalf("shell quoting altered payload: got %q, want %q", string(out), payload)
		}
		// Verify buildSSHInstallCommand downloads to a temp file before executing (no `curl | sh`).
		inst := buildSSHInstallCommand(payload)
		if strings.Contains(inst, "| sh") || !strings.Contains(inst, "mktemp") {
			t.Fatalf("install command should use mktemp download-then-execute, got: %s", inst)
		}
	}
}
