// P0-A operator CLI coverage: keys list, revoke-key, tenants
// suspend/unsuspend against a temp database. These commands are
// operator-local and DB-direct (never a Server); the relay converges
// on the committed state via admission and supervise revalidation.
package cli

import (
	"path/filepath"
	"testing"
	"time"

	"ocliv/internal/store"
)

func seedAdminDB(t *testing.T, dir string) {
	t.Helper()
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('t1','active',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES('key-1','t1',x'00','active',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at) VALUES('lse-1','t1','key-1','h.t.example.test','h',3000,'private',1,'ACTIVE',?)`, now); err != nil {
		t.Fatal(err)
	}
}

func TestRelayAdminCommands(t *testing.T) {
	dir := t.TempDir()
	seedAdminDB(t, dir)
	if code := cmdRelay([]string{"keys", "list", "--data", dir}); code != 0 {
		t.Fatalf("keys list: exit=%d", code)
	}
	if code := cmdRelay([]string{"revoke-key", "--key-id", "key-1", "--data", dir}); code != 0 {
		t.Fatalf("revoke-key: exit=%d", code)
	}
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	var kst, lst string
	if err := db.SQL().QueryRow(`SELECT status FROM agent_keys WHERE id='key-1'`).Scan(&kst); err != nil || kst != "revoked" {
		t.Fatalf("key status=%q err=%v", kst, err)
	}
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE id='lse-1'`).Scan(&lst); err != nil || lst != "REVOKED" {
		t.Fatalf("lease status=%q err=%v", lst, err)
	}
	db.Close()
	if code := cmdRelay([]string{"revoke-key", "--key-id", "key-nope", "--data", dir}); code == 0 {
		t.Fatal("revoking an unknown key exited 0")
	}
	if code := cmdRelay([]string{"tenants", "suspend", "--tenant", "t1", "--data", dir}); code != 0 {
		t.Fatalf("tenants suspend: exit=%d", code)
	}
	db, err = store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	var tst string
	if err := db.SQL().QueryRow(`SELECT status FROM tenants WHERE id='t1'`).Scan(&tst); err != nil || tst != "suspended" {
		t.Fatalf("tenant status=%q err=%v", tst, err)
	}
	db.Close()
	if code := cmdRelay([]string{"tenants", "unsuspend", "--tenant", "t1", "--data", dir}); code != 0 {
		t.Fatalf("tenants unsuspend: exit=%d", code)
	}
	if code := cmdRelay([]string{"revoke-key", "--data", dir}); code == 0 {
		t.Fatal("revoke-key without --key-id exited 0")
	}
	if code := cmdRelay([]string{"tenants", "freeze", "--tenant", "t1", "--data", dir}); code == 0 {
		t.Fatal("tenants with bad op exited 0")
	}
}
