package relay

import (
	"path/filepath"
	"testing"

	"ocliv/internal/store"
)

// TestMgmtNonceSurvivesRestart (chaos E5): a consumed management nonce
// is claimed with an atomic INSERT OR IGNORE into the SQLite-backed
// mgmt_replay table, so a relay restart must NOT resurrect it. A
// restart that cleared replay state would reopen the signed-mutation
// replay window for the full clock-skew duration.
func TestMgmtNonceSurvivesRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ocliv.db")

	open := func() (*Server, *store.DB) {
		db, err := store.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
		if err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		return s, db
	}

	s1, db1 := open()
	if !s1.consumeMgmtNonce("tenant-a", "lease-1", "nonce-restart-1") {
		_ = db1.Close()
		t.Fatal("first consumption must claim the nonce")
	}
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulated relay restart: brand-new Server over the same DB file.
	s2, db2 := open()
	defer db2.Close()
	if s2.consumeMgmtNonce("tenant-a", "lease-1", "nonce-restart-1") {
		t.Fatal("consumed nonce was accepted after restart: replay window reopened")
	}
	if !s2.consumeMgmtNonce("tenant-a", "lease-1", "nonce-restart-2") {
		t.Fatal("fresh nonce must still be claimable after restart")
	}
}
