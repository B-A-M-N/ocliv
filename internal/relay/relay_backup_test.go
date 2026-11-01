// Safe restore tests (P0-E). A restore must never silently resurrect
// revoked authority: an older snapshot missing live revocations is
// refused unless the operator explicitly resets all authority.
package relay

import (
	"os"
	"path/filepath"
	"testing"

	"ocliv/internal/store"
)

func backupTestDB(t *testing.T, dir string) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestBackupValidateRoundTrip: snapshot validates, is owner-only, and
// reopens with identical content.
func TestBackupValidateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if fi, err := os.Stat(snap); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("backup not owner-only: %v %v", fi, err)
	}
	if err := ValidateBackup(snap); err != nil {
		t.Fatalf("validate: %v", err)
	}
	var n string
	_ = db.Close()
	db2, err := store.Open(snap)
	if err != nil {
		t.Fatalf("reopen snapshot: %v", err)
	}
	defer db2.Close()
	if err := db2.SQL().QueryRow(`SELECT id FROM agent_keys WHERE id='key-1'`).Scan(&n); err != nil || n != "key-1" {
		t.Fatalf("snapshot lost key row: %q %v", n, err)
	}
}

// TestValidateRejectsTampered: a single flipped byte fails validation.
func TestValidateRejectsTampered(t *testing.T) {
	dir := t.TempDir()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(snap)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(snap, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(snap); err == nil {
		t.Fatal("tampered backup validated")
	}
}

// TestValidateRejectsUnknownNewer: a future schema version fails closed.
func TestValidateRejectsUnknownNewer(t *testing.T) {
	dir := t.TempDir()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatal(err)
	}
	future, err := store.Open(snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := future.SQL().Exec(`INSERT INTO schema_version(v, applied_at) VALUES(999, 'x')`); err != nil {
		t.Fatal(err)
	}
	_ = future.Close()
	if err := ValidateBackup(snap); err == nil {
		t.Fatal("future-schema backup validated")
	}
}

// revokeFixture builds a live DB with a revoked key, a revoked lease,
// and a tombstoned publication, plus returns the pre-revocation
// snapshot path.
func revokeFixture(t *testing.T, dir string) (snapBefore string) {
	t.Helper()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	if _, err := db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		 VALUES('lse-1','tenant-1','key-1','a.t.example.test','a',3000,?,1,'ACTIVE','2026-01-01T00:00:00Z')`,
		AccessModeMCPUpstreamOAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, lease_id, created_at, updated_at)
		 VALUES('r-route1','tenant-1','key-1','public.example.org','upstream-oauth','a','lse-1','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	snapBefore = filepath.Join(t.TempDir(), "before.db")
	if err := BackupState(db, snapBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := RevokeAgentKeyDB(db, "key-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	return snapBefore
}

// TestRestoreRefusesRevocationRollback: restoring the pre-revocation
// snapshot over live revoked state is refused, and live state is
// untouched.
func TestRestoreRefusesRevocationRollback(t *testing.T) {
	dir := t.TempDir()
	snapBefore := revokeFixture(t, dir)
	if err := RestoreState(dir, snapBefore, false, true); err == nil {
		t.Fatal("rollback restore accepted without --reset-authority")
	}
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var st string
	if err := db.SQL().QueryRow(`SELECT status FROM agent_keys WHERE id='key-1'`).Scan(&st); err != nil || st != "revoked" {
		t.Fatalf("live revocation lost after refused restore: %q %v", st, err)
	}
	var tomb string
	if err := db.SQL().QueryRow(`SELECT revoked_at FROM mcp_publications WHERE route_id='r-route1'`).Scan(&tomb); err != nil || tomb == "" {
		t.Fatalf("live tombstone lost after refused restore: %q %v", tomb, err)
	}
}

// terminalFixture snapshots an active lease with an active publication,
// then moves the live database to the given terminal state. It returns
// the pre-terminal snapshot path.
func terminalFixture(t *testing.T, dir, leaseStatus, pubAction string) (snapBefore string) {
	t.Helper()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	if _, err := db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, token_generation, status, created_at)
		 VALUES('lse-1','tenant-1','key-1','a.t.example.test','a',3000,?,1,0,'ACTIVE','2026-01-01T00:00:00Z')`,
		AccessModeMCPUpstreamOAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`INSERT INTO mcp_publications(route_id, tenant_id, owner_key_id, external_host, profile, pub_name, lease_id, created_at, updated_at, verified_at)
		 VALUES('r-route1','tenant-1','key-1','public.example.org','upstream-oauth','a','lse-1','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	snapBefore = filepath.Join(t.TempDir(), "before.db")
	if err := BackupState(db, snapBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`UPDATE leases SET status=? WHERE id='lse-1'`, leaseStatus); err != nil {
		t.Fatal(err)
	}
	switch pubAction {
	case "delete":
		if _, err := db.SQL().Exec(`DELETE FROM mcp_publications WHERE route_id='r-route1'`); err != nil {
			t.Fatal(err)
		}
	case "bump-token-gen":
		if _, err := db.SQL().Exec(`UPDATE leases SET token_generation=token_generation+1 WHERE id='lse-1'`); err != nil {
			t.Fatal(err)
		}
	case "bump-generation":
		if _, err := db.SQL().Exec(`UPDATE leases SET generation=generation+4 WHERE id='lse-1'`); err != nil {
			t.Fatal(err)
		}
	}
	return snapBefore
}

// TestRestoreRefusesClosedLeaseRollback: a pre-close ACTIVE snapshot
// restored over a CLOSED lease is refused — close is terminal, and
// boot reconciliation must never see the lease ACTIVE again.
func TestRestoreRefusesClosedLeaseRollback(t *testing.T) {
	dir := t.TempDir()
	snapBefore := terminalFixture(t, dir, "CLOSED", "keep")
	if err := RestoreState(dir, snapBefore, false, true); err == nil {
		t.Fatal("closed-lease rollback restore accepted")
	}
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var st string
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id='lse-1'`).Scan(&st); err != nil || st != "CLOSED" {
		t.Fatalf("live CLOSED lease lost after refused restore: %q %v", st, err)
	}
}

// TestRestoreRefusesExpiredLeaseRollback: same terminality for EXPIRED.
func TestRestoreRefusesExpiredLeaseRollback(t *testing.T) {
	dir := t.TempDir()
	snapBefore := terminalFixture(t, dir, "EXPIRED", "keep")
	if err := RestoreState(dir, snapBefore, false, true); err == nil {
		t.Fatal("expired-lease rollback restore accepted")
	}
}

// TestRestoreRefusesDeletedPublication: a publication explicitly
// unpublished (row deleted) after the snapshot must not reappear.
func TestRestoreRefusesDeletedPublication(t *testing.T) {
	dir := t.TempDir()
	snapBefore := terminalFixture(t, dir, "ACTIVE", "delete")
	if err := RestoreState(dir, snapBefore, false, true); err == nil {
		t.Fatal("deleted-publication resurrection restore accepted")
	}
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("deleted publication reappeared after refused restore: n=%d err=%v", n, err)
	}
}

// TestRestoreRefusesTokenRotationRollback: a post-backup credential
// rotation (token_generation bump) must not be undone by restore —
// the older snapshot would revalidate rotated-out tokens.
func TestRestoreRefusesTokenRotationRollback(t *testing.T) {
	dir := t.TempDir()
	snapBefore := terminalFixture(t, dir, "ACTIVE", "bump-token-gen")
	if err := RestoreState(dir, snapBefore, false, true); err == nil {
		t.Fatal("token-rotation rollback restore accepted")
	}
}

// TestRestoreRefusesFencingGenerationRollback: post-backup reconnects
// (generation bumps) must not be undone by restore — the older snapshot
// would let a superseded generation fence and regain live authority.
func TestRestoreRefusesFencingGenerationRollback(t *testing.T) {
	dir := t.TempDir()
	snapBefore := terminalFixture(t, dir, "ACTIVE", "bump-generation")
	if err := RestoreState(dir, snapBefore, false, true); err == nil {
		t.Fatal("generation-rollback restore accepted")
	}
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var g int64
	if err := db.SQL().QueryRow(`SELECT generation FROM leases WHERE id='lse-1'`).Scan(&g); err != nil || g != 5 {
		t.Fatalf("live fencing generation lost after refused restore: %d %v", g, err)
	}
}

// TestRestoreRefusesSameFile: source and destination must differ.
func TestRestoreRefusesSameFile(t *testing.T) {
	dir := t.TempDir()
	db := backupTestDB(t, dir)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	live := filepath.Join(dir, relayDBName)
	_ = db.Close()
	if err := RestoreState(dir, live, false, true); err == nil {
		t.Fatal("same-file restore accepted")
	}
}

// TestRestoreRefusesSymlinkedDataDir: a symlinked data directory would
// install the database somewhere the operator did not audit.
func TestRestoreRefusesSymlinkedDataDir(t *testing.T) {
	real := t.TempDir()
	db := backupTestDB(t, real)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	linkParent := t.TempDir()
	link := filepath.Join(linkParent, "data-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(link, snap, false, true); err == nil {
		t.Fatal("symlinked-datadir restore accepted")
	}
}

// TestRestoreRequiresStoppedAttestation: without the operator's
// stopped attestation, restore refuses even a clean snapshot.
func TestRestoreRequiresStoppedAttestation(t *testing.T) {
	src := t.TempDir()
	db := backupTestDB(t, src)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatal(err)
	}
	if err := RestoreState(t.TempDir(), snap, false, false); err == nil {
		t.Fatal("online restore accepted without --relay-stopped")
	}
}

// TestRestorePreservesOwnership: a current snapshot restores cleanly
// with non-revoked authority intact and schema usable.
func TestRestorePreservesOwnership(t *testing.T) {
	src := t.TempDir()
	db := backupTestDB(t, src)
	enrollTestKey(t, db.SQL(), "key-1", "tenant-1")
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := BackupState(db, snap); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := RestoreState(dst, snap, false, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored, err := store.Open(filepath.Join(dst, relayDBName))
	if err != nil {
		t.Fatalf("reopen restored: %v", err)
	}
	defer restored.Close()
	var st string
	if err := restored.SQL().QueryRow(`SELECT status FROM agent_keys WHERE id='key-1'`).Scan(&st); err != nil || st != "active" {
		t.Fatalf("restored key not active: %q %v", st, err)
	}
	var check string
	if err := restored.SQL().QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("restored integrity: %q %v", check, err)
	}
}

// TestRestoreResetAuthority: with reset, everything restored is
// distrusted — keys revoked, leases terminal, publications tombstoned —
// while rows and schema survive for audit and re-enrollment.
func TestRestoreResetAuthority(t *testing.T) {
	dir := t.TempDir()
	snapBefore := revokeFixture(t, dir)
	// snapBefore predates the fixture revocation: plain restore would
	// refuse, but reset-authority explicitly distrusts everything.
	if err := RestoreState(dir, snapBefore, true, true); err != nil {
		t.Fatalf("reset restore: %v", err)
	}
	db, err := store.Open(filepath.Join(dir, relayDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var st string
	if err := db.SQL().QueryRow(`SELECT status FROM agent_keys WHERE id='key-1'`).Scan(&st); err != nil || st != "revoked" {
		t.Fatalf("reset did not revoke key: %q %v", st, err)
	}
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id='lse-1'`).Scan(&st); err != nil || st != "REVOKED" {
		t.Fatalf("reset did not revoke lease: %q %v", st, err)
	}
	var tomb *string
	if err := db.SQL().QueryRow(`SELECT revoked_at FROM mcp_publications WHERE route_id='r-route1'`).Scan(&tomb); err != nil || tomb == nil || *tomb == "" {
		t.Fatalf("reset did not tombstone publication: %v %v", tomb, err)
	}
	var mode string
	if err := db.SQL().QueryRow(`SELECT detail FROM audit_events WHERE category='restore+reset-authority' ORDER BY id DESC LIMIT 1`).Scan(&mode); err != nil {
		t.Fatalf("restore not audited: %v", err)
	}
}
