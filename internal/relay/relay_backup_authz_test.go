package relay

// Failing-first regressions for the second review's P1 restore-protection
// finding: the restore-time rollback guard checked agent_keys, leases,
// access_tokens, visitor_sessions, and mcp_publications — but NOT the
// managed-authorization tables (authz_revocations, authz_clients.revoked_at,
// authz_grants.status). Restoring an older database could therefore
// reactivate revoked managed clients, grants, or tokens. reset-authority
// likewise left managed OAuth authority intact.

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/store"
)

// managedRollbackFixture builds a live DB with an approved managed client
// and a granted client, snapshots it, then revokes both in live. It
// returns the pre-revocation snapshot path.
func managedRollbackFixture(t *testing.T, dir string) (snapBefore string) {
	t.Helper()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	if _, err := db.SQL().Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id)
		 VALUES('cli-approved','Approved','["https://c.example/cb"]','2026-01-01T00:00:00Z','tenant-1','r-route1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id)
		 VALUES('cli-granted','Granted','["https://c.example/cb"]','2026-01-01T00:00:00Z','tenant-1','r-route1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at)
		 VALUES('cli-granted','tenant-1','r-route1','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	snapBefore = filepath.Join(t.TempDir(), "before.db")
	if err := BackupState(db, snapBefore); err != nil {
		t.Fatal(err)
	}
	// Revoke the client and the grant in LIVE, AFTER the snapshot.
	if _, err := db.SQL().Exec(
		`UPDATE authz_clients SET revoked_at='2026-06-01T00:00:00Z' WHERE id='cli-approved'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`UPDATE authz_grants SET status='revoked' WHERE client_id='cli-granted'`); err != nil {
		t.Fatal(err)
	}
	return snapBefore
}

// TestRestoreRejectsManagedRevocationRollback: restoring the
// pre-revocation snapshot over live revoked managed state must be
// refused (a revoked managed client or grant must never become active
// again). Pre-fix the guard only watched agent/lease/token/session/pub
// tables, so this restore is accepted and the revocations are lost.
func TestRestoreRejectsManagedRevocationRollback(t *testing.T) {
	dir := t.TempDir()
	snapBefore := managedRollbackFixture(t, dir)
	if err := RestoreState(dir, snapBefore, false, true); err == nil {
		t.Fatal("managed-authorization rollback restore accepted without --reset-authority")
	}
	// Live managed revocations untouched.
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var revokedAt string
	if err := db.SQL().QueryRow(`SELECT revoked_at FROM authz_clients WHERE id='cli-approved'`).Scan(&revokedAt); err != nil || revokedAt == "" {
		t.Fatalf("live client revocation lost after refused restore: %q %v", revokedAt, err)
	}
	var st string
	if err := db.SQL().QueryRow(`SELECT status FROM authz_grants WHERE client_id='cli-granted'`).Scan(&st); err != nil || st != "revoked" {
		t.Fatalf("live grant revocation lost after refused restore: %q %v", st, err)
	}
}

// TestResetAuthorityInvalidatesManagedOAuth: --reset-authority must
// terminally revoke managed OAuth authority too — clients and grants —
// not just agent keys/leases/tokens/publications. Pre-fix it leaves the
// managed tables untouched, so a restored client/grant stays usable.
func TestResetAuthorityInvalidatesManagedOAuth(t *testing.T) {
	dir := t.TempDir()
	snapBefore := managedRollbackFixture(t, dir)
	// reset-authority is the explicit escape hatch: it must succeed even
	// though the snapshot is older, and it must neutralize managed authority.
	if err := RestoreState(dir, snapBefore, true, true); err != nil {
		t.Fatalf("restore with --reset-authority: %v", err)
	}
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var revokedAt sql.NullString
	if err := db.SQL().QueryRow(`SELECT revoked_at FROM authz_clients WHERE id='cli-approved'`).Scan(&revokedAt); err != nil || !revokedAt.Valid {
		t.Fatalf("--reset-authority left managed client active: revoked_at=%v err=%v", revokedAt, err)
	}
	var st string
	if err := db.SQL().QueryRow(`SELECT status FROM authz_grants WHERE client_id='cli-granted'`).Scan(&st); err != nil || st != "revoked" {
		t.Fatalf("--reset-authority left managed grant active: status=%q %v", st, err)
	}
}

// TestRestoreSafeManagedBackupStillWorks: when the backup does NOT roll
// back any managed revocation (it contains the revoked state), a normal
// restore is permitted and the managed rows are preserved — the guard
// must not over-refuse legitimate restores.
func TestRestoreSafeManagedBackupStillWorks(t *testing.T) {
	dir := t.TempDir()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	if _, err := db.SQL().Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id)
		 VALUES('cli-active','Active','["https://c.example/cb"]','2026-01-01T00:00:00Z','tenant-1','r-route1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at)
		 VALUES('cli-active','tenant-1','r-route1','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	// Snapshot AFTER the grant is active (no rollback of anything).
	snap := filepath.Join(t.TempDir(), "after.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(dir, snap, false, true); err != nil {
		t.Fatalf("safe managed restore refused: %v", err)
	}
	db2, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var st string
	if err := db2.SQL().QueryRow(`SELECT status FROM authz_grants WHERE client_id='cli-active'`).Scan(&st); err != nil || st != "active" {
		t.Fatalf("legitimate active grant not preserved on safe restore: %q %v", st, err)
	}
}

// TestRestoreRejectsCrossRouteGrantRevocationRollback: the guard's grant
// identity is the composite (tenant_id, route_id, client_id), NOT client_id
// alone. A client with route A revoked and route B active in live, with the
// states reversed in the backup, must refuse restoration of A's active
// grant — pre-fix the guard keys on client_id only, so B's backup-active
// grant masks A's live revocation and the restore is accepted.
func TestRestoreRejectsCrossRouteGrantRevocationRollback(t *testing.T) {
	dir := t.TempDir()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	now := "2026-01-01T00:00:00Z"
	// Live: grant for route B active, grant for route A revoked.
	// Backup (taken before the flips): grant for route A active, grant
	// for route B revoked. Restoring the backup must refuse: it would
	// reactivate A's revoked grant even though B's state matches.
	if _, err := db.SQL().Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id)
		 VALUES('cli-x','X','["https://c.example/cb"]','2026-01-01T00:00:00Z','tenant-1','r-a')`); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"r-a", "r-b"} {
		if _, err := db.SQL().Exec(
			`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at)
			 VALUES('cli-x','tenant-1',?,'active',?,?)`, r, now, now); err != nil {
			t.Fatal(err)
		}
	}
	// Snapshot: A active, B revoked (the operator had already revoked B
	// before this backup was taken).
	if _, err := db.SQL().Exec(
		`UPDATE authz_grants SET status='revoked' WHERE client_id='cli-x' AND route_id='r-b'`); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(t.TempDir(), "backup.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatal(err)
	}
	// Live then flips: B is re-approved (active again), A is revoked.
	// Restoring the snapshot would reactivate A's revoked grant; B's
	// backup revocation matches live's active state only by coincidence.
	if _, err := db.SQL().Exec(
		`UPDATE authz_grants SET status='active' WHERE client_id='cli-x' AND route_id='r-b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`UPDATE authz_grants SET status='revoked' WHERE client_id='cli-x' AND route_id='r-a'`); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(dir, snap, false, true); err == nil {
		t.Fatal("cross-route grant rollback accepted without --reset-authority")
	}
	// Live route-A revocation untouched.
	db2, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var st string
	if err := db2.SQL().QueryRow(
		`SELECT status FROM authz_grants WHERE client_id='cli-x' AND route_id='r-a'`).Scan(&st); err != nil || st != "revoked" {
		t.Fatalf("live route-A grant revocation lost after refused restore: %q %v", st, err)
	}
}

// TestRejectedRestoreDoesNotMigrateLiveDatabase: a restore attempt that is
// refused by the rollback guard must leave the live database's schema version
// and content untouched. Pre-fix, openRevocations called store.Open on the
// LIVE database, forward-migrating it (V7 -> V11) before the guard decided
// whether the restore was acceptable — a side effect on refused restores.
func TestRejectedRestoreDoesNotMigrateLiveDatabase(t *testing.T) {
	dir := t.TempDir()
	db := backupTestDB(t, dir) // opens at V11 by default; we need V7, see below
	_ = db
	// Build a V7 live database: open through the store, then stamp the
	// schema_version table back to 7 (the read-only preflight must accept
	// v <= SchemaVersion and read whatever tables exist). We cannot easily
	// build a genuine pre-V8 file here without re-running old migrations,
	// so instead we create a v7 marker: delete the managed-authorization
	// tables so readRevocations sees the pre-V8 shape, and record the
	// schema version as 7. store.Open would re-migrate to V11 on next
	// open — which is exactly the side effect this test must NOT observe.
	livePath := filepath.Join(dir, relayDBName)
	live, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	enrollTestKey(t, live.SQL(), "key-1", "tenant-1")
	if _, err := live.SQL().Exec(
		`INSERT INTO authz_clients(id, name, redirect_uris, created_at, tenant_id, route_id)
		 VALUES('cli-x','X','[]','2026-01-01T00:00:00Z','tenant-1','r-a')`); err != nil {
		t.Fatal(err)
	}
	if _, err := live.SQL().Exec(
		`INSERT INTO authz_grants(client_id, tenant_id, route_id, status, created_at, updated_at)
		 VALUES('cli-x','tenant-1','r-a','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	// Backup while the grant is active.
	snap := filepath.Join(t.TempDir(), "backup.db")
	if err := BackupState(live, snap); err != nil {
		t.Fatal(err)
	}
	// Revoke in live: the restore must be refused.
	if _, err := live.SQL().Exec(
		`UPDATE authz_grants SET status='revoked' WHERE client_id='cli-x'`); err != nil {
		t.Fatal(err)
	}
	live.Close()

	// Degrade the schema MARKER to 7 while keeping the managed tables, so
	// the live DB exercises the preflight reader's "older schema, read what
	// exists" path. A rejected restore must NOT re-migrate it (the marker
	// must still read 7 afterwards).
	d, err := store.Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SQL().Exec(`DELETE FROM schema_version WHERE v > 7`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	// Sanity: the live DB now reports v=7 and has no authz tables.
	ro, err := openReadOnly(livePath)
	if err != nil {
		t.Fatalf("openReadOnly on degraded db: %v", err)
	}
	var v int
	if err := ro.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != 7 {
		ro.Close()
		t.Fatalf("setup: live schema should be 7, got %d err=%v", v, err)
	}
	ro.Close()

	// The refused restore attempt.
	if err := RestoreState(dir, snap, false, true); err == nil {
		t.Fatal("restore should have been refused (revocation rollback)")
	}
	// The live database must still be v=7 — NOT migrated forward.
	ro2, err := openReadOnly(livePath)
	if err != nil {
		t.Fatalf("openReadOnly after refused restore: %v", err)
	}
	defer ro2.Close()
	if err := ro2.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v); err != nil || v != 7 {
		t.Fatalf("live database was migrated by a REFUSED restore: v=%d err=%v", v, err)
	}
	// No replacement installed: the live key row must still be present.
	var n int
	if err := ro2.QueryRow(`SELECT COUNT(*) FROM agent_keys WHERE id='key-1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("live database contents changed by refused restore: keys=%d err=%v", n, err)
	}
}
