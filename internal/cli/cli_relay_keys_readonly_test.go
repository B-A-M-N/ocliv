package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/store"
)

func TestRelayKeysListDoesNotCreateDatabase(t *testing.T) {
	dir := t.TempDir()
	if code := cmdRelay([]string{"keys", "list", "--data", dir}); code == 0 {
		t.Fatal("keys list on a missing database succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, "ocliv.db")); !os.IsNotExist(err) {
		t.Fatalf("read-only keys list created the database: stat err=%v", err)
	}
}

func TestRelayKeysListDoesNotMigrateV7Database(t *testing.T) {
	dir := t.TempDir()
	seedAdminDB(t, dir)
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"authz_consent", "authz_audit", "authz_revocations", "authz_issuer_key",
		"authz_codes", "authz_grants", "authz_clients",
	} {
		if _, err := db.SQL().Exec("DROP TABLE " + table); err != nil {
			db.Close()
			t.Fatalf("remove post-v7 table %s: %v", table, err)
		}
	}
	if _, err := db.SQL().Exec(`DELETE FROM schema_version WHERE v > 7`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ocliv.db")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if code := cmdRelay([]string{"keys", "list", "--data", dir}); code != 0 {
		t.Fatalf("keys list on V7: exit=%d", code)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("keys list changed the V7 database bytes")
	}
	ro, err := openRelayDBReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	var version int
	if err := ro.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&version); err != nil || version != 7 {
		t.Fatalf("schema version after keys list=%d err=%v; want 7", version, err)
	}
}
