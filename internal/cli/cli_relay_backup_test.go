// P0-E operator CLI coverage: backup writes a restorable snapshot;
// restore refuses without --relay-stopped, refuses revocation rollback,
// and applies cleanly with reset-authority.
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"ocliv/internal/store"
)

func TestRelayBackupRestoreCommands(t *testing.T) {
	dir := t.TempDir()
	seedAdminDB(t, dir)
	snap := filepath.Join(t.TempDir(), "snap.db")
	if code := cmdRelay([]string{"backup", "--data", dir, "--out", snap}); code != 0 {
		t.Fatalf("backup: exit=%d", code)
	}
	fi, err := os.Stat(snap)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("backup missing or empty: %v %v", fi, err)
	}

	// Without the stopped attestation, restore refuses.
	if code := cmdRelay([]string{"restore", "--data", dir, "--in", snap}); code == 0 {
		t.Fatal("restore without --relay-stopped exited 0")
	}

	// Revoke after the snapshot, then prove rollback is refused.
	if code := cmdRelay([]string{"revoke-key", "--key-id", "key-1", "--data", dir}); code != 0 {
		t.Fatalf("revoke-key: exit=%d", code)
	}
	if code := cmdRelay([]string{"restore", "--data", dir, "--in", snap, "--relay-stopped"}); code == 0 {
		t.Fatal("rollback restore exited 0")
	}

	// Reset-authority applies: key stays revoked afterwards.
	if code := cmdRelay([]string{"restore", "--data", dir, "--in", snap, "--relay-stopped", "--reset-authority"}); code != 0 {
		t.Fatalf("reset restore: exit=%d", code)
	}
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var st string
	if err := db.SQL().QueryRow(`SELECT status FROM agent_keys WHERE id='key-1'`).Scan(&st); err != nil || st != "revoked" {
		t.Fatalf("key status after reset restore=%q err=%v", st, err)
	}

	// A fresh snapshot of current (revoked) state restores cleanly.
	snap2 := filepath.Join(t.TempDir(), "snap2.db")
	if code := cmdRelay([]string{"backup", "--data", dir, "--out", snap2}); code != 0 {
		t.Fatalf("backup2: exit=%d", code)
	}
	dst := t.TempDir()
	if code := cmdRelay([]string{"restore", "--data", dst, "--in", snap2, "--relay-stopped"}); code != 0 {
		t.Fatalf("restore into fresh dir: exit=%d", code)
	}
}
