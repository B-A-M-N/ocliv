package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

// TestRelaySignedManagementNativeConsentApproval verifies that an enrolled
// publisher can list and approve a specific pending OAuth authorization
// transaction over Ocliv's Ed25519-signed management channel (with zero
// pairing secrets copied and zero external IdP), while non-owner keys are
// rejected fail-closed.
func TestRelaySignedManagementNativeConsentApproval(t *testing.T) {
	db := backupTestDB(t, t.TempDir())
	mgr, err := newAuthzManager(db)
	if err != nil {
		t.Fatalf("newAuthzManager: %v", err)
	}
	srv := &Server{
		db:      db,
		authz:   mgr,
		mcpHost: "relay.example",
		mcpPort: 443,
	}

	ownerKey, _ := identity.Generate()
	ownerKeyID := "key-" + string(ownerKey.ID())
	otherKey, _ := identity.Generate()
	otherKeyID := "key-" + string(otherKey.ID())
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('t-nat', 'active', ?)`, now)
	_, _ = db.SQL().Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,'active',?)`, ownerKeyID, "t-nat", []byte(ownerKey.Public()), now)
	_, _ = db.SQL().Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,'active',?)`, otherKeyID, "t-nat", []byte(otherKey.Public()), now)

	routeID := "NatRoute0123456789abcd"
	_, _ = db.SQL().Exec(
		`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, created_at, updated_at, verified_at, desired_enabled, state_generation)
		 VALUES(?, 't-nat', ?, 'relay.example', 'managed-oauth', 'natpub', ?, ?, ?, 1, 1)`,
		routeID, ownerKeyID, now, now, now)

	if err := mgr.Store().TryRegisterClientWithPendingGrant(authz.Client{
		ID: "cli_nat_1", Name: "ChatGPT", RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		Tenant: "t-nat", Route: routeID,
	}, "t-nat", routeID); err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := mgr.Store().CreateConsent(authz.Consent{
		Challenge:     "cns_tx_12345",
		ClientID:      "cli_nat_1",
		Tenant:        "t-nat",
		Route:         routeID,
		RedirectURI:   "https://chatgpt.com/connector_platform_oauth_redirect",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		State:         "st-1",
		Resource:      "https://relay.example/r/" + routeID + "/mcp",
		Scope:         "mcp:tools offline_access",
		ExpiresAt:     time.Now().UTC().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateConsent: %v", err)
	}

	// 1. Owner lists pending transactions.
	listRec := httptest.NewRecorder()
	srv.handleAgentPublications(listRec, signMgmtReq(t, ownerKey, http.MethodGet, "/v1/agent/mcp-routes/"+routeID+"/authz/pending", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET pending status=%d body=%s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		PendingTransactions []authz.Consent `json:"pending_transactions"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil || len(listResp.PendingTransactions) != 1 || listResp.PendingTransactions[0].Challenge != "cns_tx_12345" {
		t.Fatalf("unexpected pending_transactions: %s", listRec.Body.String())
	}

	// 2. Non-owner key MUST be refused (404).
	otherRec := httptest.NewRecorder()
	srv.handleAgentPublications(otherRec, signMgmtReq(t, otherKey, http.MethodPost, "/v1/agent/mcp-routes/"+routeID+"/authz/consents/cns_tx_12345/approve", nil))
	if otherRec.Code != http.StatusNotFound {
		t.Fatalf("non-owner approval status=%d, want 404", otherRec.Code)
	}

	// 3. Owner approves transaction over signed management channel (no pairing secret!).
	appRec := httptest.NewRecorder()
	srv.handleAgentPublications(appRec, signMgmtReq(t, ownerKey, http.MethodPost, "/v1/agent/mcp-routes/"+routeID+"/authz/consents/cns_tx_12345/approve", nil))
	if appRec.Code != http.StatusOK {
		t.Fatalf("owner approve status=%d body=%s", appRec.Code, appRec.Body.String())
	}
	var appResp struct {
		Challenge string `json:"challenge"`
		ClientID  string `json:"client_id"`
		Decision  string `json:"decision"`
	}
	if err := json.Unmarshal(appRec.Body.Bytes(), &appResp); err != nil || appResp.Decision != "approved" || appResp.ClientID != "cli_nat_1" {
		t.Fatalf("unexpected approve response: %s", appRec.Body.String())
	}
	g, err := mgr.Store().GetGrant("cli_nat_1", "t-nat", routeID)
	if err != nil || g.Status != authz.GrantActive || g.Provenance.Method != authz.GrantMethodOperatorTx || g.SkipPairing {
		t.Fatalf("unexpected grant after signed native approval: %+v err=%v", g, err)
	}
}
