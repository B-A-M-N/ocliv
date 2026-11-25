package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/agent"
	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/identity"
	"github.com/B-A-M-N/ocliv/internal/store"
)

func signMgmtReq(t *testing.T, k *identity.KeyPair, method, path string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, "https://relay.example"+path, bytes.NewReader(body))
	keyID := "key-" + string(k.ID())
	ts := time.Now().UTC()
	nonce := ""
	if method != http.MethodGet {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		nonce = base64.StdEncoding.EncodeToString(buf)
		req.Header.Set("X-Ocliv-Nonce", nonce)
	}
	req.Header.Set("X-Ocliv-Key", keyID)
	req.Header.Set("X-Ocliv-TS", ts.Format(time.RFC3339Nano))
	var sig []byte
	if len(body) > 0 {
		digest := agent.MgmtBodySHA256(body)
		sig = ed25519.Sign(k.Private(), agent.MgmtMessageV2(keyID, method, path, ts, nonce, digest))
		req.Header.Set("X-Ocliv-Sig-Version", "2")
		req.Header.Set("X-Ocliv-Body-SHA256", digest)
		req.Header.Set("Content-Type", "application/json")
	} else {
		sig = ed25519.Sign(k.Private(), agent.MgmtMessage(keyID, method, path, ts, nonce))
	}
	req.Header.Set("X-Ocliv-Sig", base64.StdEncoding.EncodeToString(sig))
	return req
}

func TestRelayTrustPolicyOwnershipAndAtomicDelete(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

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

	ownerKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate owner key: %v", err)
	}
	otherKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate other key: %v", err)
	}
	ownerKeyID := "key-" + string(ownerKey.ID())
	otherKeyID := "key-" + string(otherKey.ID())
	now := time.Now().UTC().Format(time.RFC3339Nano)

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES(?, 'active', ?)`, tenant, now); err != nil {
			t.Fatalf("insert tenant: %v", err)
		}
	}
	if _, err := db.SQL().Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?, 'active', ?)`,
		ownerKeyID, "tenant-a", []byte(ownerKey.Public()), now); err != nil {
		t.Fatalf("insert owner key: %v", err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?, 'active', ?)`,
		otherKeyID, "tenant-a", []byte(otherKey.Public()), now); err != nil {
		t.Fatalf("insert other key: %v", err)
	}

	routeID := "AbCdEfGhIjKlMnOpQrStUv"
	if _, err := db.SQL().Exec(
		`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, created_at, updated_at, verified_at, desired_enabled, state_generation)
		 VALUES(?, 'tenant-a', ?, 'relay.example', 'managed-oauth', 'tools', ?, ?, ?, 1, 1)`,
		routeID, ownerKeyID, now, now, now); err != nil {
		t.Fatalf("insert publication: %v", err)
	}

	// 1. Unauthorized key (same tenant, different owner) cannot add trust policy.
	addBody, _ := json.Marshal(map[string]any{"kind": "chatgpt"})
	rec := httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, otherKey, http.MethodPost, "/v1/agent/mcp-routes/"+routeID+"/trust", addBody))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unauthorized owner POST trust status=%d, want 404", rec.Code)
	}

	// 2. Owner adds chatgpt trust policy -> 201 Created.
	rec = httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, ownerKey, http.MethodPost, "/v1/agent/mcp-routes/"+routeID+"/trust", addBody))
	if rec.Code != http.StatusCreated {
		t.Fatalf("owner POST trust status=%d body=%s, want 201", rec.Code, rec.Body.String())
	}

	// 3. Publication view includes trusted_clients: ["ChatGPT"].
	rec = httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, ownerKey, http.MethodGet, "/v1/agent/mcp-routes/"+routeID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET publication status=%d body=%s", rec.Code, rec.Body.String())
	}
	var pubView agentPublicationView
	if err := json.Unmarshal(rec.Body.Bytes(), &pubView); err != nil {
		t.Fatalf("decode pubView: %v", err)
	}
	if len(pubView.TrustedClients) != 1 || pubView.TrustedClients[0] != "ChatGPT" {
		t.Fatalf("expected TrustedClients=[ChatGPT], got %v", pubView.TrustedClients)
	}

	// 4. Unauthorized key cannot list or revoke trust policy.
	rec = httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, otherKey, http.MethodGet, "/v1/agent/mcp-routes/"+routeID+"/trust", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unauthorized GET trust status=%d, want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, otherKey, http.MethodDelete, "/v1/agent/mcp-routes/"+routeID+"/trust/chatgpt", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unauthorized DELETE trust status=%d, want 404", rec.Code)
	}

	// 5. Deleting publication atomically revokes its trust policies.
	rec = httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, ownerKey, http.MethodDelete, "/v1/agent/mcp-routes/"+routeID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE publication status=%d body=%s", rec.Code, rec.Body.String())
	}
	policies, err := mgr.Store().ListTrustPolicies("tenant-a", routeID)
	if err != nil {
		t.Fatalf("ListTrustPolicies: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected 0 active trust policies after publication delete, got %d", len(policies))
	}
}

func TestRestoreRejectsTrustPolicyRevocationRollback(t *testing.T) {
	dir := t.TempDir()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")

	authzStore := authz.NewSQLStore(db.SQL())
	if err := authzStore.CreateTrustPolicy(authz.ClientTrustPolicy{
		ID:           "tp_test_1",
		TenantID:     "tenant-1",
		RouteID:      "r-route1",
		OwnerKeyID:   "key-1",
		Kind:         "chatgpt",
		RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		Enabled:      true,
	}); err != nil {
		t.Fatalf("CreateTrustPolicy: %v", err)
	}

	snapBefore := filepath.Join(t.TempDir(), "before.db")
	if err := BackupState(db, snapBefore); err != nil {
		t.Fatalf("BackupState: %v", err)
	}

	// Revoke policy in live DB after snapshot.
	if _, err := authzStore.RevokeTrustPolicy("tenant-1", "r-route1", "tp_test_1"); err != nil {
		t.Fatalf("RevokeTrustPolicy: %v", err)
	}

	// Restoring older snapshot without --reset-authority must fail closed.
	if err := RestoreState(dir, snapBefore, false, true); err == nil {
		t.Fatal("expected restore to refuse resurrecting revoked trust policy")
	}

	// Restoring with --reset-authority succeeds and revokes all trust policies.
	if err := RestoreState(dir, snapBefore, true, true); err != nil {
		t.Fatalf("RestoreState --reset-authority: %v", err)
	}
	reopened, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	var revokedAt sql.NullString
	var enabled int
	if err := reopened.SQL().QueryRow(`SELECT enabled, revoked_at FROM authz_trust_policies WHERE id='tp_test_1'`).Scan(&enabled, &revokedAt); err != nil {
		t.Fatalf("query trust policy: %v", err)
	}
	if enabled != 0 || !revokedAt.Valid {
		t.Fatalf("--reset-authority left trust policy active: enabled=%d revoked_at=%v", enabled, revokedAt)
	}
}

// OCL-005 & OCL-006: Relay visitor-auth policy management enforces ownership,
// redacts client_secret on GET/PUT responses, atomically revokes dependent
// grants on DELETE, and blocks backup revocation rollback.
func TestRelayVisitorAuthPolicyOwnershipRevocationAndBackupGuard(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

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
	otherKey, _ := identity.Generate()
	ownerKeyID := "key-" + string(ownerKey.ID())
	otherKeyID := "key-" + string(otherKey.ID())
	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, _ = db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('tenant-a', 'active', ?)`, now)
	_, _ = db.SQL().Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,'active',?)`, ownerKeyID, "tenant-a", []byte(ownerKey.Public()), now)
	_, _ = db.SQL().Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,'active',?)`, otherKeyID, "tenant-a", []byte(otherKey.Public()), now)

	routeID := "FedRoute0123456789abcd"
	_, _ = db.SQL().Exec(
		`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, created_at, updated_at, verified_at, desired_enabled, state_generation)
		 VALUES(?, 'tenant-a', ?, 'relay.example', 'managed-oauth', 'priv', ?, ?, ?, 1, 1)`,
		routeID, ownerKeyID, now, now, now)

	setBody, _ := json.Marshal(map[string]any{
		"mode":             "federated",
		"issuer":           "https://idp.example",
		"client_id":        "ocliv-idp-cid",
		"client_secret":    "top-secret-idp-value",
		"allowed_subjects": []string{"auth0|owner-1"},
		"client_policy":    "chatgpt",
	})

	// Unauthorized key rejected with 404.
	rec := httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, otherKey, http.MethodPut, "/v1/agent/mcp-routes/"+routeID+"/visitor-auth", setBody))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unauthorized PUT visitor-auth status=%d, want 404", rec.Code)
	}

	// Owner sets federated visitor auth policy; response redacts client_secret.
	rec = httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, ownerKey, http.MethodPut, "/v1/agent/mcp-routes/"+routeID+"/visitor-auth", setBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("owner PUT visitor-auth status=%d body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("top-secret-idp-value")) {
		t.Fatalf("PUT visitor-auth response leaked client_secret: %s", rec.Body.String())
	}

	// GET returns redacted policy.
	rec = httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, ownerKey, http.MethodGet, "/v1/agent/mcp-routes/"+routeID+"/visitor-auth", nil))
	if rec.Code != http.StatusOK || bytes.Contains(rec.Body.Bytes(), []byte("top-secret-idp-value")) {
		t.Fatalf("GET visitor-auth status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Seed a federated grant and take a backup before revoking.
	_ = mgr.Store().RegisterClient(authz.Client{
		ID: "cli_fed_1", Name: "ChatGPT", RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		Tenant: "tenant-a", Route: routeID,
	})
	if err := mgr.Store().ApproveGrantWithProvenance("cli_fed_1", "tenant-a", routeID, false, authz.GrantProvenance{
		Method: authz.GrantMethodFederatedOIDC, OwnerIssuer: "https://idp.example", OwnerSubject: "auth0|owner-1",
	}); err != nil {
		t.Fatalf("ApproveGrantWithProvenance: %v", err)
	}

	snap := filepath.Join(t.TempDir(), "before-fed-revoke.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatalf("BackupState: %v", err)
	}

	// Owner revokes visitor-auth -> dependent federated grant atomically revoked.
	rec = httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, ownerKey, http.MethodDelete, "/v1/agent/mcp-routes/"+routeID+"/visitor-auth", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE visitor-auth status=%d body=%s", rec.Code, rec.Body.String())
	}
	if g, err := mgr.Store().GetGrant("cli_fed_1", "tenant-a", routeID); err != nil || g.Status != authz.GrantRevoked {
		t.Fatalf("dependent federated grant not revoked: %+v err=%v", g, err)
	}

	// Restore of pre-revocation snapshot without --reset-authority must fail closed.
	db.Close()
	if err := RestoreState(dir, snap, false, true); err == nil {
		t.Fatal("expected RestoreState to reject rolling back revoked visitor-auth policy")
	}
}

// OCL-009: Relay host observations record real MCP/Events stages separately
// from synthetic probe traffic and never store tokens or payloads.
func TestRelayObservationsEndpointSeparatesSyntheticFromExternalHost(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

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
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('tenant-obs', 'active', ?)`, now)
	_, _ = db.SQL().Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,'active',?)`, ownerKeyID, "tenant-obs", []byte(ownerKey.Public()), now)

	routeID := "ObsRoute0123456789abcd"
	_, _ = db.SQL().Exec(
		`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, created_at, updated_at, verified_at, desired_enabled, state_generation)
		 VALUES(?, 'tenant-obs', ?, 'relay.example', 'managed-oauth', 'evpub', ?, ?, ?, 1, 5)`,
		routeID, ownerKeyID, now, now, now)
	_ = mgr.Store().RegisterClient(authz.Client{
		ID: "cli_cgpt_obs", Name: "ChatGPT", RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
		Tenant: "tenant-obs", Route: routeID,
	})

	rt := &routeTarget{TenantID: "tenant-obs", RouteID: routeID}
	// Synthetic probe events/subscribe must be tagged synthetic and NOT advance real host stage.
	srv.recordManagedMCPObservation(rt, "cli_cgpt_obs", "events/subscribe", "2026-07-28", true, http.StatusOK)
	// Real client events/list advances real stage to EVENTS_DISCOVERY_OBSERVED.
	srv.recordManagedMCPObservation(rt, "cli_cgpt_obs", "events/list", "2026-07-28", false, http.StatusOK)

	rec := httptest.NewRecorder()
	srv.handleAgentPublications(rec, signMgmtReq(t, ownerKey, http.MethodGet, "/v1/agent/mcp-routes/"+routeID+"/observations", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET observations status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Verification authz.HostVerificationSummary `json:"verification"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode observations: %v", err)
	}
	v := resp.Verification
	if v.HighestStage != authz.StageEventsDiscoveryObserved {
		t.Fatalf("HighestStage=%q, want EVENTS_DISCOVERY_OBSERVED (synthetic subscribe must not promote real stage)", v.HighestStage)
	}
	if v.EventsSubscriptionObserved != "UNKNOWN" || v.EventsDiscoveryObserved != "OBSERVED" || !v.PresetClientObserved {
		t.Fatalf("unexpected verification summary: %+v", v)
	}
	if v.ExternalAcceptance != authz.StageExternalAcceptanceUnverified {
		t.Fatalf("ExternalAcceptance=%q, want EXTERNAL_ACCEPTANCE_UNVERIFIED", v.ExternalAcceptance)
	}
}
