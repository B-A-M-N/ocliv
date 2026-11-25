package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestOCL012ManageControlPlanePermissionsAndSingleCallGetURL(t *testing.T) {
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
			ServiceID:     "svc_agw",
			Name:          "agentgateway",
			OwnerKeyID:    keyID,
			RelayID:       relayAuthority("https://bamnlabs.duckdns.org"),
			PublicationID: "jr8x2Txyoa1jPs22CROuBQ",
		},
	}); err != nil {
		t.Fatalf("put agentgateway: %v", err)
	}

	// Write operator-controlled 0600 permissions policy: lifecycle allowed,
	// authorize_visitor & remove_publication DENIED.
	polPath := filepath.Join(t.TempDir(), "agent-permissions.json")
	polJSON := `{
		"agent_permissions": {
			"inspect": true,
			"get_url": true,
			"verify": true,
			"lifecycle": true,
			"deployment": false,
			"authorize_visitor": false,
			"revoke_client": false,
			"remove_publication": false
		},
		"allowed_services": ["agentgateway"]
	}`
	if err := os.WriteFile(polPath, []byte(polJSON), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	t.Setenv("OCLIV_PERMISSIONS_FILE", polPath)

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
			return http.StatusNotFound, []byte("not found"), nil
		},
	}

	// 1. Single-call get_url returns canonical URL and reachability.
	raw, err := handleMCPManageTool("get_url", map[string]any{"service": "agentgateway"}, "https://bamnlabs.duckdns.org", k, keyID, ops)
	if err != nil {
		t.Fatalf("get_url: %v", err)
	}
	m := raw.(map[string]any)
	if m["url"] != "https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp" || m["enabled"] != true || m["reachable"] != true {
		t.Fatalf("unexpected get_url result: %+v", m)
	}

	// 2. Privilege escalation to decide_authorization fails closed.
	if _, err := handleMCPManageTool("decide_authorization", map[string]any{
		"service": "agentgateway", "challenge": "cns_1", "decision": "approve",
	}, "https://bamnlabs.duckdns.org", k, keyID, ops); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied for decide_authorization, got %v", err)
	}

	// 3. Unauthorized service target fails closed.
	if _, err := handleMCPManageTool("get_service", map[string]any{"service": "other-svc"}, "https://bamnlabs.duckdns.org", k, keyID, ops); err == nil || !strings.Contains(err.Error(), "allowed_services") {
		t.Fatalf("expected allowed_services denial for other-svc, got %v", err)
	}

	// 4. Insecure permissions file mode (0644) fails closed.
	if err := os.Chmod(polPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := handleMCPManageTool("get_url", map[string]any{"service": "agentgateway"}, "https://bamnlabs.duckdns.org", k, keyID, ops); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected 0600 mode check failure, got %v", err)
	}
}
