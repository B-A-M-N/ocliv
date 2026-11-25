package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestOCL013ManageControlPlanePermissionsLifecycleAndHonestVerification(t *testing.T) {
	seedEnrolledProfileForTest(t, "https://bamnlabs.duckdns.org")
	k, keyID, err := loadKeyForProfile(config.ActiveProfile())
	if err != nil {
		t.Fatalf("loadKeyForProfile: %v", err)
	}
	store, err := openServices()
	if err != nil {
		t.Fatalf("openServices: %v", err)
	}
	if err := store.Put(config.ServiceRecord{
		Name:          "agentgateway",
		Type:          "mcp",
		LocalURL:      "http://127.0.0.1:8765/mcp",
		Auth:          "ocliv-managed",
		Profile:       config.ActiveProfile(),
		RelayURL:      "https://bamnlabs.duckdns.org",
		DesiredState:  config.DesiredEnabled,
		PublicationID: "jr8x2Txyoa1jPs22CROuBQ",
		PublicURL:     "https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp",
		SystemdUnit:   "ocliv-publisher@agentgateway.service",
		Identity: &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     "svc_agw_immutable",
			Name:          "agentgateway",
			OwnerKeyID:    keyID,
			RelayID:       relayAuthority("https://bamnlabs.duckdns.org"),
			PublicationID: "jr8x2Txyoa1jPs22CROuBQ",
		},
	}); err != nil {
		t.Fatalf("put agentgateway: %v", err)
	}
	// Restricted second service that agent-ops MUST NOT discover.
	if err := store.Put(config.ServiceRecord{
		Name:         "restricted-db",
		Type:         "mcp",
		LocalURL:     "http://127.0.0.1:9999/mcp",
		Auth:         "ocliv-managed",
		Profile:      config.ActiveProfile(),
		RelayURL:     "https://bamnlabs.duckdns.org",
		DesiredState: config.DesiredDisabled,
	}); err != nil {
		t.Fatalf("put restricted-db: %v", err)
	}

	tmpDir := t.TempDir()
	polPath := filepath.Join(tmpDir, "agent-permissions.json")
	reqPath := filepath.Join(tmpDir, "approval-requests.json")
	t.Setenv("OCLIV_PERMISSIONS_FILE", polPath)
	t.Setenv("OCLIV_APPROVAL_REQUESTS_FILE", reqPath)

	pol := AgentPermissionsPolicy{
		Agents: map[string]AgentPermissionRule{
			"agent-ops": {
				AgentPermissions: AgentPermissionsFlags{
					Inspect:           true,
					GetURL:            true,
					Verify:            true,
					Lifecycle:         true,
					Deployment:        true,
					AuthorizeVisitor:  true,
					ManageAuthPolicy:  false, // strictly separate!
					RevokeClient:      false,
					RemovePublication: true,
				},
				AllowedServices:  []string{"agentgateway"},
				AllowedPorts:     []int{8765, 8085},
				AllowedAuthModes: []string{"ocliv-managed"},
			},
			"agent-empty": {
				AgentPermissions: AgentPermissionsFlags{Inspect: true, Deployment: true},
				// Empty AllowedServices and AllowedPorts MUST deny all!
			},
		},
	}
	if err := saveAgentPermissionsPolicy(pol); err != nil {
		t.Fatalf("saveAgentPermissionsPolicy: %v", err)
	}

	invBody, _ := json.Marshal(map[string]any{
		"publications": []relayPublication{
			{
				RouteID:          "jr8x2Txyoa1jPs22CROuBQ",
				Name:             "agentgateway",
				Profile:          "managed-oauth",
				URL:              strPtr("https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp"),
				LeaseID:          strPtr("lease-1"),
				PublicationState: "VERIFIED",
				DesiredEnabled:   true,
				StateGeneration:  2,
				SessionLive:      true,
				HostBinding:      "VALID",
				Admission:        "READY",
				AdmissionReason:  "READY",
			},
		},
	})
	clientsBody := `{"publication_id":"jr8x2Txyoa1jPs22CROuBQ","clients":[{"client_id":"cli_1","client_name":"ChatGPT","auth_method":"native","status":"approved","publication_id":"jr8x2Txyoa1jPs22CROuBQ","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"authorized_at":"2026-11-25T10:00:00Z","updated_at":"2026-11-25T10:00:00Z"}]}`

	relayFailWrites := false
	ops := serviceOps{
		systemctl: func(args ...string) (string, error) {
			return "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n", nil
		},
		probeLoc: func(string, time.Duration) error { return nil },
		probePub: func(string, time.Duration) (int, error) { return http.StatusUnauthorized, nil },
		mgmtCall: func(_ string, _ *identity.KeyPair, _, method, path string) (int, []byte, error) {
			if method == http.MethodGet && path == "/v1/agent/mcp-routes" {
				return http.StatusOK, invBody, nil
			}
			if method == http.MethodGet && path == "/v1/agent/mcp-routes/jr8x2Txyoa1jPs22CROuBQ/authz/clients" {
				return http.StatusOK, []byte(clientsBody), nil
			}
			if relayFailWrites && (method == http.MethodPost || method == http.MethodDelete) {
				return 0, nil, errors.New("relay unreachable")
			}
			return http.StatusNotFound, []byte("not found"), nil
		},
	}

	// 1. list_services filters out restricted-db for agent-ops, and returns 0 for agent-empty.
	listRaw, err := handleMCPManageTool("agent-ops", "list_services", nil, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("list_services: %v", err)
	}
	svcs := listRaw.(map[string]any)["services"].([]map[string]any)
	if len(svcs) != 1 || svcs[0]["name"] != "agentgateway" {
		t.Fatalf("list_services leaked restricted service: %+v", svcs)
	}
	emptyRaw, _ := handleMCPManageTool("agent-empty", "list_services", nil, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if len(emptyRaw.(map[string]any)["services"].([]map[string]any)) != 0 {
		t.Fatal("empty allowed_services must not act as wildcard")
	}

	// 2. Single-call get_url returns canonical URL + reachability.
	urlRaw, err := handleMCPManageTool("agent-ops", "get_url", map[string]any{"service": "agentgateway"}, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("get_url: %v", err)
	}
	if urlRaw.(map[string]any)["url"] != "https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp" || urlRaw.(map[string]any)["reachable"] != true {
		t.Fatalf("unexpected get_url: %+v", urlRaw)
	}

	// 3. Deployment configuration conflict fails closed instead of returning fake idempotent: true.
	confRaw, err := handleMCPManageTool("agent-ops", "deploy_service", map[string]any{
		"name": "agentgateway", "port": 8085, "type": "mcp", "authentication": "ocliv-managed",
	}, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("deploy_service conflict: %v", err)
	}
	if confRaw.(map[string]any)["status"] != "CONFIGURATION_CONFLICT" {
		t.Fatalf("expected CONFIGURATION_CONFLICT, got %+v", confRaw)
	}

	// 4. Authoritative list_authorized_clients returns real relay OAuth client inventory.
	cliRaw, err := handleMCPManageTool("agent-ops", "list_authorized_clients", map[string]any{"service": "agentgateway"}, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("list_authorized_clients: %v", err)
	}
	if cliRaw.(map[string]any)["ok"] != true {
		t.Fatalf("expected authoritative clients ok=true, got %+v", cliRaw)
	}

	// 5. authorize_visitor does NOT grant manage_auth_policy; denied call creates actionable approval request!
	polDenyRaw, err := handleMCPManageTool("agent-ops", "set_auth_policy", map[string]any{
		"service": "agentgateway", "preset": "chatgpt",
	}, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("set_auth_policy deny: %v", err)
	}
	polDeny := polDenyRaw.(map[string]any)
	if polDeny["status"] != "OPERATOR_AUTHORIZATION_REQUIRED" || polDeny["request_id"] == "" {
		t.Fatalf("expected OPERATOR_AUTHORIZATION_REQUIRED with request_id, got %+v", polDeny)
	}

	// 6. Failed relay disable & remove MUST return UNCONFIRMED and preserve the local record!
	relayFailWrites = true
	disRaw, err := handleMCPManageTool("agent-ops", "disable_service", map[string]any{"service": "agentgateway"}, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("disable_service: %v", err)
	}
	if disRaw.(map[string]any)["confirmed"] != false || disRaw.(map[string]any)["status"] != "UNCONFIRMED" {
		t.Fatalf("failed relay disable must report UNCONFIRMED, got %+v", disRaw)
	}
	remRaw, err := handleMCPManageTool("agent-ops", "remove_service", map[string]any{"service": "agentgateway"}, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("remove_service: %v", err)
	}
	if remRaw.(map[string]any)["confirmed"] != false || remRaw.(map[string]any)["record_kept"] != true {
		t.Fatalf("failed relay remove must preserve record and return UNCONFIRMED, got %+v", remRaw)
	}
	if _, stillThere, _ := store.Get("agentgateway"); !stillThere {
		t.Fatal("local service record was deleted despite unconfirmed remote revocation")
	}

	// 7. Insecure permissions file mode (0644) fails closed.
	if err := os.Chmod(polPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := handleMCPManageTool("agent-ops", "get_url", map[string]any{"service": "agentgateway"}, "https://bamnlabs.duckdns.org", k, keyID, ops); err == nil {
		t.Fatal("expected 0644 permissions file to fail closed")
	}
}
