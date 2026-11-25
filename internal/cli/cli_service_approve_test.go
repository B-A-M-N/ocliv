package cli

import (
	"net/http"
	"slices"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestBuildVersionInfoAdvertisesNativeAndEventsCapabilities(t *testing.T) {
	info := buildVersionInfo()
	caps, ok := info["capabilities"].([]string)
	if !ok {
		t.Fatalf("capabilities missing or wrong type: %T", info["capabilities"])
	}
	for _, want := range []string{"native_tx_authz", "optional_federated_oidc", "mcp_events_qualification", "host_observations"} {
		if !slices.Contains(caps, want) {
			t.Fatalf("version capabilities missing %q: %v", want, caps)
		}
	}
}

func TestServiceApproveRejectsConflictsAndNoImplicitLegacyFallback(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://relay.example")
	store, err := openServices()
	if err != nil {
		t.Fatalf("openServices: %v", err)
	}
	if err := store.Put(config.ServiceRecord{
		Name:          "tools",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:8765/mcp",
		RelayURL:      "https://relay.example",
		PublicationID: "pub-tools-1",
		Profile:       config.ActiveProfile(),
	}); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	calledLegacyApprove := false
	calledTxApprove := false
	ops := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes/pub-tools-1/authz/pending" {
				// One pending client, ZERO pending authorization transactions!
				return 200, []byte(`{"pending":[{"client_id":"cli_1","name":"ChatGPT"}],"pending_transactions":[]}`), nil
			}
			if method == http.MethodPost && path == "/v1/agent/mcp-routes/pub-tools-1/authz/approve/cli_1" {
				calledLegacyApprove = true
				return 200, []byte(`{"client_id":"cli_1","pairing_secret":"pair_secret"}`), nil
			}
			if method == http.MethodPost && path == "/v1/agent/mcp-routes/pub-tools-1/authz/consents/cns_123/approve" {
				calledTxApprove = true
				return 200, []byte(`{"challenge":"cns_123","client_id":"cli_1","decision":"approved"}`), nil
			}
			return 404, []byte("not found"), nil
		},
	}

	// 1. Default `ocliv service approve tools --json` with 0 pending transactions MUST NOT fall back to legacy pairing!
	if code := cmdServiceApprove([]string{"tools", "--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("expected ExitOK for AWAITING_AUTHORIZATION_REQUEST, got %d", code)
	}
	if calledLegacyApprove {
		t.Fatal("default approve silently fell back into legacy pairing-secret issuance!")
	}

	// 2. Conflicting flags fail closed.
	for _, argv := range [][]string{
		{"tools", "--challenge", "cns_123", "--direct"},
		{"tools", "--challenge", "cns_123", "--client", "cli_1"},
		{"tools", "--direct", "--legacy-pairing", "--client", "cli_1"},
		{"tools", "--client", "cli_1"},
		{"tools", "--deny", "--client", "cli_1"},
	} {
		if code := cmdServiceApprove(argv, ops); code != apperr.ExitCLIValidation {
			t.Fatalf("expected ExitCLIValidation for %v, got %d", argv, code)
		}
	}

	// 3. Explicit --challenge approves exact transaction.
	if code := cmdServiceApprove([]string{"tools", "--challenge", "cns_123", "--json"}, ops); code != apperr.ExitOK {
		t.Fatalf("explicit --challenge approve exit=%d, want 0", code)
	}
	if !calledTxApprove {
		t.Fatal("expected exact transaction consent approve call")
	}

	// 4. Non-interactive approve with 1 pending transaction but NO --challenge MUST fail closed (CHALLENGE_REQUIRED).
	opsOneTx := serviceOps{
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes/pub-tools-1/authz/pending" {
				return 200, []byte(`{"pending":[],"pending_transactions":[{"challenge":"cns_only","client_id":"cli_1","client_name":"ChatGPT","redirect_uri":"https://chatgpt.com/connector_platform_oauth_redirect","scope":"mcp:tools"}]}`), nil
			}
			t.Fatalf("unexpected mutation call without explicit --challenge: %s %s", method, path)
			return 500, nil, nil
		},
	}
	if code := cmdServiceApprove([]string{"tools", "--json"}, opsOneTx); code != apperr.ExitCLIValidation {
		t.Fatalf("non-interactive approve without --challenge must fail closed, got %d", code)
	}
}
