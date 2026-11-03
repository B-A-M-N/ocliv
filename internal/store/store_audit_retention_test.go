package store

import (
	"testing"
	"time"
)

// Audit retention (Stage 6, chaos finding A2): audit_events grows on every
// denied request with no pruning path, so months of probing fill the disk
// and bloat backups. PruneAuditEvents deletes rows older than the
// documented retention window; recent security evidence is preserved.
func TestPruneAuditEventsKeepsRecentEvidence(t *testing.T) {
	db, err := Open(t.TempDir() + "/ocliv.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	seed := func(ts time.Time, category string) {
		t.Helper()
		if _, err := db.SQL().Exec(
			`INSERT INTO audit_events(time, actor, tenant_id, lease_id, category, result, detail) VALUES(?,?,?,?,?,?,?)`,
			ts.Format(time.RFC3339Nano), "visitor", "", "", category, "denied", "probe"); err != nil {
			t.Fatal(err)
		}
	}
	seed(now.Add(-120*24*time.Hour), "stale-probe")
	seed(now.Add(-time.Hour), "recent-probe")
	seed(now.Add(time.Hour), "future-probe")

	deleted, err := db.PruneAuditEvents(now)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("pruned %d rows, want exactly the stale row", deleted)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("remaining rows: n=%d err=%v, want 2", n, err)
	}
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE category='stale-probe'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stale row survived: n=%d err=%v", n, err)
	}

	// Idempotent: a second sweep deletes nothing.
	deleted, err = db.PruneAuditEvents(now)
	if err != nil || deleted != 0 {
		t.Fatalf("repeat prune: deleted=%d err=%v, want 0/<nil>", deleted, err)
	}
}
