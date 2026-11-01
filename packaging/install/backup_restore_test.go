package install_test

// Restore safety tests (P0-C): a backup that drops a live revocation
// must be refused, never served; a revocation-preserving backup restores.

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const restoreScript = "../../packaging/install/backup-restore.sh"

func requireSQLite3(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 CLI not available")
	}
}

func fakeBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// systemctl reports the relay as not active so the offline check passes.
	sh := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(sh), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mkdb(t *testing.T, path, schemaV string, revokedLease string) {
	t.Helper()
	stmts := `
CREATE TABLE schema_version (v INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE agent_keys (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, ed25519_public BLOB NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE leases (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_key_id TEXT NOT NULL, hostname TEXT NOT NULL UNIQUE, label TEXT NOT NULL, port INTEGER NOT NULL, access_mode TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1, token_generation INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, expires_at TEXT, reconnect_until TEXT, created_at TEXT NOT NULL);
CREATE TABLE access_tokens (id TEXT PRIMARY KEY, lease_id TEXT NOT NULL, verifier TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'visitor', created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, max_uses INTEGER NOT NULL DEFAULT 1, uses INTEGER NOT NULL DEFAULT 0);
CREATE TABLE visitor_sessions (id TEXT PRIMARY KEY, lease_id TEXT NOT NULL, token_generation INTEGER NOT NULL DEFAULT 0, session_verifier TEXT NOT NULL, created_at TEXT NOT NULL, idle_expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL, revoked_at TEXT);
INSERT INTO schema_version(v, applied_at) VALUES(` + schemaV + `, 'now');
`
	if revokedLease != "" {
		stmts += `INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, status, created_at)
VALUES('` + revokedLease + `', 't', 'k', 'h', 'l', 3000, 'protected', 'REVOKED', 'now');`
	}
	cmd := exec.Command("sqlite3", path, stmts)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mkdb: %v %s", err, out)
	}
}

func runRestore(t *testing.T, dataDir, src string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", restoreScript, "restore", src)
	cmd.Env = append([]string{"PATH=" + fakeBin(t) + ":/usr/bin:/bin", "DATA_DIR=" + dataDir}, os.Environ()...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return string(out), code
}

func TestRestoreRefusesRevocationRollback(t *testing.T) {
	requireSQLite3(t)
	dir := t.TempDir()
	live := filepath.Join(dir, "ocliv.db")
	mkdb(t, live, "3", "lse-revoked")
	stale := filepath.Join(dir, "stale.db")
	// Stale backup: same lease present but ACTIVE — the rollback case a
	// bare revoked-count check would miss if counts happened to match.
	mkdb(t, stale, "3", "")
	if out, err := exec.Command("sqlite3", stale,
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, status, created_at)
VALUES('lse-revoked','t','k','h','l',3000,'protected','ACTIVE','now');`).CombinedOutput(); err != nil {
		t.Fatalf("seed stale: %v %s", err, out)
	}
	out, code := runRestore(t, dir, stale)
	if code == 0 {
		t.Fatalf("restore accepted a revocation rollback: %s", out)
	}
	// Live DB untouched: lease still REVOKED.
	chk, err := exec.Command("sqlite3", live,
		`SELECT status FROM leases WHERE id='lse-revoked';`).CombinedOutput()
	if err != nil || string(chk) != "REVOKED\n" {
		t.Fatalf("live DB altered by refused restore: %v %q", err, chk)
	}
}

func TestRestoreAcceptsRevocationPreservingBackup(t *testing.T) {
	requireSQLite3(t)
	dir := t.TempDir()
	live := filepath.Join(dir, "ocliv.db")
	mkdb(t, live, "3", "lse-revoked")
	good := filepath.Join(dir, "good.db")
	mkdb(t, good, "3", "lse-revoked")
	if out, code := runRestore(t, dir, good); code != 0 {
		t.Fatalf("restore refused a safe backup: %s", out)
	}
}
