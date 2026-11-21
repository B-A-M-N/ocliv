package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"ocliv/internal/apperr"
)

func TestPairingV21MigrationAndCorruptTimestamp(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ocliv.db")
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Insert a pairing row with a corrupt expires_at timestamp and verify scanPairingRequest
	// returns CodeStoreFault rather than silently zeroing ExpiresAt.
	_, err = db.SQL().Exec(
		`INSERT INTO pairing_requests(id, display_code, poll_id, poll_verifier, public_key, key_id, source_ip, status, created_at, expires_at)
		 VALUES('p-corrupt','aaaa-bbbb-cccc','poll-corrupt',X'0102',X'00','key-abc','127.0.0.1','pending',?,'not-a-timestamp')`,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetPairingRequestByPollID("poll-corrupt"); err == nil || apperr.CodeOf(err) != apperr.CodeStoreFault {
		t.Fatalf("expected CodeStoreFault on corrupt timestamp, got %v (code=%v)", err, apperr.CodeOf(err))
	}
}

func TestV20LegacyPendingInvalidatedOnMigration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.db")
	// Build a DB at schema V19 with a legacy pending pairing request (no poll_verifier).
	sqldb, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6, schemaV7,
		schemaV8, schemaV9, schemaV10, schemaV11, schemaV12, schemaV13, schemaV14,
		schemaV15, schemaV16, schemaV17, schemaV18, schemaV19,
	} {
		if _, err := sqldb.Exec(stmt); err != nil {
			sqldb.Close()
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	exp := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
	if _, err := sqldb.Exec(`INSERT OR REPLACE INTO schema_version(v, applied_at) VALUES(19, ?)`, now); err != nil {
		sqldb.Close()
		t.Fatal(err)
	}
	// Legacy pending row (no poll_verifier) + legacy approved row (tenant in enrollment_code_id).
	if _, err := sqldb.Exec(
		`INSERT INTO pairing_requests(id, display_code, public_key, key_id, source_ip, status, created_at, expires_at)
		 VALUES('old-pend','1111-2222-3333',X'00','key-old','127.0.0.1','pending',?,?)`, now, exp); err != nil {
		sqldb.Close()
		t.Fatal(err)
	}
	if _, err := sqldb.Exec(
		`INSERT INTO pairing_requests(id, display_code, public_key, key_id, source_ip, status, created_at, expires_at, resolved_at, enrollment_code_id)
		 VALUES('old-app','4444-5555-6666',X'00','key-app','127.0.0.1','approved',?,?,?,'tenant-legacy')`, now, exp, now); err != nil {
		sqldb.Close()
		t.Fatal(err)
	}
	sqldb.Close()

	// Opening with current binary migrates V19 -> V20 -> V21.
	db, err := Open(p)
	if err != nil {
		t.Fatalf("Open migration failed: %v", err)
	}
	defer db.Close()

	prPend, err := db.GetPairingRequest("1111-2222-3333")
	if err != nil {
		t.Fatal(err)
	}
	if prPend.Status != "expired" {
		t.Fatalf("legacy V19 pending request status=%q, want expired", prPend.Status)
	}

	prApp, err := db.GetPairingRequest("4444-5555-6666")
	if err != nil {
		t.Fatal(err)
	}
	if prApp.ResolvedTenantID != "tenant-legacy" {
		t.Fatalf("backfilled resolved_tenant_id=%q, want tenant-legacy", prApp.ResolvedTenantID)
	}
}

func TestPruneTerminalLeaseEphemeraPreservesTombstones(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	old := now.Add(-60 * 24 * time.Hour).Format(time.RFC3339Nano)
	_, err = db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, status, created_at)
		 VALUES('lse-term','t1','k1','x.t.test','x',8080,'private','REVOKED',?)`, old)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.SQL().Exec(
		`INSERT INTO visitor_sessions(id, lease_id, session_verifier, created_at, idle_expires_at, absolute_expires_at)
		 VALUES('vs-1','lse-term','ver',?,?,?)`, old, old, old)
	if err != nil {
		t.Fatal(err)
	}
	pruned, err := db.PruneTerminalLeaseEphemera(now, TerminalLeaseEphemeraRetention)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("pruned=%d, want 1", pruned)
	}
	var leaseCount int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM leases WHERE id='lse-term'`).Scan(&leaseCount); err != nil || leaseCount != 1 {
		t.Fatalf("terminal lease tombstone must never be deleted: count=%d err=%v", leaseCount, err)
	}
}

func TestV21DuplicatePendingDeduplicatedOnV22Migration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v21dup.db")
	sqldb, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6, schemaV7,
		schemaV8, schemaV9, schemaV10, schemaV11, schemaV12, schemaV13, schemaV14,
		schemaV15, schemaV16, schemaV17, schemaV18, schemaV19, schemaV20, schemaV21,
	} {
		if _, err := sqldb.Exec(stmt); err != nil {
			sqldb.Close()
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	exp := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
	if _, err := sqldb.Exec(`INSERT OR REPLACE INTO schema_version(v, applied_at) VALUES(21, ?)`, now); err != nil {
		sqldb.Close()
		t.Fatal(err)
	}
	// Plant 2 live pending rows for the SAME key_id in V21 (legal in V21, illegal in V22).
	for i, code := range []string{"aaaa-1111-2222", "bbbb-3333-4444"} {
		if _, err := sqldb.Exec(
			`INSERT INTO pairing_requests(id, display_code, poll_id, poll_verifier, public_key, key_id, source_ip, status, created_at, expires_at)
			 VALUES(?,?,?,X'0102',X'00','key-dup','127.0.0.1','pending',?,?)`,
			"dup-"+string(rune('1'+i)), code, "poll-"+string(rune('1'+i)), now, exp); err != nil {
			sqldb.Close()
			t.Fatal(err)
		}
	}
	sqldb.Close()

	// Migrating V21 -> V22 must expire the older duplicate BEFORE creating the partial unique index.
	db, err := Open(p)
	if err != nil {
		t.Fatalf("V21->V22 migration failed on duplicate pending rows: %v", err)
	}
	defer db.Close()

	var pend int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM pairing_requests WHERE key_id='key-dup' AND status='pending'`).Scan(&pend); err != nil || pend != 1 {
		t.Fatalf("expected 1 surviving pending row after V22 migration, got %d (err=%v)", pend, err)
	}
	// Re-opening an already-V22 DB must be a clean no-op.
	db.Close()
	db2, err := Open(p)
	if err != nil {
		t.Fatalf("already-V22 reopen failed: %v", err)
	}
	db2.Close()
}

func TestV20ToV22MigrationWithDuplicatePending(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v20dup.db")
	sqldb, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6, schemaV7,
		schemaV8, schemaV9, schemaV10, schemaV11, schemaV12, schemaV13, schemaV14,
		schemaV15, schemaV16, schemaV17, schemaV18, schemaV19, schemaV20,
	} {
		if _, err := sqldb.Exec(stmt); err != nil {
			sqldb.Close()
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	exp := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
	if _, err := sqldb.Exec(`INSERT OR REPLACE INTO schema_version(v, applied_at) VALUES(20, ?)`, now); err != nil {
		sqldb.Close()
		t.Fatal(err)
	}
	// Duplicate pending rows for the same key_id + an approved legacy row in V20.
	for i, code := range []string{"cccc-1111-2222", "dddd-3333-4444"} {
		if _, err := sqldb.Exec(
			`INSERT INTO pairing_requests(id, display_code, poll_id, poll_verifier, public_key, key_id, source_ip, status, created_at, expires_at)
			 VALUES(?,?,?,X'0102',X'00','key-v20-dup','127.0.0.1','pending',?,?)`,
			"v20-dup-"+string(rune('1'+i)), code, "v20-poll-"+string(rune('1'+i)), now, exp); err != nil {
			sqldb.Close()
			t.Fatal(err)
		}
	}
	if _, err := sqldb.Exec(
		`INSERT INTO pairing_requests(id, display_code, poll_id, poll_verifier, public_key, key_id, source_ip, status, created_at, expires_at, resolved_at, enrollment_code_id)
		 VALUES('v20-app','eeee-5555-6666','v20-poll-app',X'0102',X'00','key-v20-app','127.0.0.1','approved',?,?,?,'tenant-v20')`,
		now, exp, now); err != nil {
		sqldb.Close()
		t.Fatal(err)
	}
	sqldb.Close()

	db, err := Open(p)
	if err != nil {
		t.Fatalf("V20->V22 migration failed: %v", err)
	}
	defer db.Close()

	var pend int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM pairing_requests WHERE key_id='key-v20-dup' AND status='pending'`).Scan(&pend); err != nil || pend != 1 {
		t.Fatalf("expected 1 surviving pending row after V20->V22 migration, got %d (err=%v)", pend, err)
	}
	prApp, err := db.GetPairingRequest("eeee-5555-6666")
	if err != nil {
		t.Fatal(err)
	}
	if prApp.ResolvedTenantID != "tenant-v20" {
		t.Fatalf("V20->V22 resolved_tenant_id=%q, want tenant-v20", prApp.ResolvedTenantID)
	}
}
