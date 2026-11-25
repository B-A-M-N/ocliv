package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestV23ToV24MigrationQuarantinesLegacyDirectGrants verifies that upgrading a
// real V23 database containing an active automatically-trusted client grant
// (skip_pairing=1) to V24 explicitly tags it as auth_method='legacy' AND
// quarantines skip_pairing=0 so it cannot bypass authorization until
// reauthorized (OCL-005, OCL-006).
func TestV23ToV24MigrationQuarantinesLegacyDirectGrants(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v23-upgrade.db")
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("fk: %v", err)
	}
	if _, err := raw.Exec(schemaV1); err != nil {
		t.Fatalf("schemaV1: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO schema_version(v, applied_at) VALUES(1, '2026-11-20T00:00:00Z')`); err != nil {
		t.Fatalf("record v1: %v", err)
	}
	v2To23 := []struct {
		v   int
		sql string
	}{
		{2, schemaV2}, {3, schemaV3}, {4, schemaV4}, {5, schemaV5},
		{6, schemaV6}, {7, schemaV7}, {8, schemaV8}, {9, schemaV9},
		{10, schemaV10}, {11, schemaV11}, {12, schemaV12}, {13, schemaV13},
		{14, schemaV14}, {15, schemaV15}, {16, schemaV16}, {17, schemaV17},
		{18, schemaV18}, {19, schemaV19}, {20, schemaV20}, {21, schemaV21},
		{22, schemaV22}, {23, schemaV23},
	}
	for _, m := range v2To23 {
		if err := applyMigration(raw, m.v, m.sql); err != nil {
			t.Fatalf("apply schemaV%d: %v", m.v, err)
		}
	}

	// Seed a V23 trust policy + auto-trusted client with an active skip_pairing=1 grant.
	if _, err := raw.Exec(
		`INSERT INTO authz_trust_policies(id, tenant_id, route_id, owner_key_id, kind, redirect_uris_json, enabled, created_at)
		 VALUES('tp_v23', 'tenant-a', 'route-1', 'key-1', 'chatgpt', '["https://chatgpt.com/connector_platform_oauth_redirect"]', 1, '2026-11-20T00:00:00Z')`,
	); err != nil {
		t.Fatalf("seed v23 trust policy: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id)
		 VALUES('cli_v23_auto', 'ChatGPT-V23', '["https://chatgpt.com/connector_platform_oauth_redirect"]', '2026-11-20T00:00:00Z', 'tenant-a', 'route-1')`,
	); err != nil {
		t.Fatalf("seed v23 client: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at, skip_pairing)
		 VALUES('cli_v23_auto', 'tenant-a', 'route-1', 'active', '2026-11-20T00:00:00Z', '2026-11-20T00:00:00Z', 1)`,
	); err != nil {
		t.Fatalf("seed v23 grant: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw v23: %v", err)
	}

	// Open with store.Open to run the real forward migration from V23 -> V24.
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open(v23->v24): %v", err)
	}
	defer db.Close()

	var version int
	if err := db.SQL().QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&version); err != nil || version != SchemaVersion {
		t.Fatalf("schema version = %d (err=%v), want %d", version, err, SchemaVersion)
	}

	var (
		status        string
		skipPairing   int
		authMethod    string
		trustPolicyID string
	)
	if err := db.SQL().QueryRow(
		`SELECT status, skip_pairing, auth_method, trust_policy_id
		 FROM authz_grants WHERE client_id='cli_v23_auto' AND tenant_id='tenant-a' AND route_id='route-1'`,
	).Scan(&status, &skipPairing, &authMethod, &trustPolicyID); err != nil {
		t.Fatalf("read migrated grant: %v", err)
	}
	if authMethod != "legacy" {
		t.Fatalf("migrated grant auth_method=%q, want 'legacy'", authMethod)
	}
	if skipPairing != 0 {
		t.Fatalf("migrated legacy grant skip_pairing=%d, want 0 (quarantined until reauthorized)", skipPairing)
	}
	if trustPolicyID != "" {
		t.Fatalf("migrated legacy grant trust_policy_id=%q, want empty", trustPolicyID)
	}

	// Verify V24 columns exist on new tables.
	var colCount int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM pragma_table_info('authz_visitor_policies') WHERE name='revision'`).Scan(&colCount); err != nil || colCount != 1 {
		t.Fatalf("authz_visitor_policies.revision missing: count=%d err=%v", colCount, err)
	}
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM pragma_table_info('authz_oidc_tx') WHERE name='visitor_policy_revision'`).Scan(&colCount); err != nil || colCount != 1 {
		t.Fatalf("authz_oidc_tx.visitor_policy_revision missing: count=%d err=%v", colCount, err)
	}
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM pragma_table_info('mcp_host_observations') WHERE name='transport_ok'`).Scan(&colCount); err != nil || colCount != 1 {
		t.Fatalf("mcp_host_observations.transport_ok missing: count=%d err=%v", colCount, err)
	}
}
