package relay

import (
	"path/filepath"
	"testing"
	"time"

	"ocliv/internal/store"
)

// reconcileBoot must enforce the audit retention window (Stage 6, chaos
// finding A2): a relay restart converges durable state, and unbounded
// audit growth must not survive it.
func TestReconcileBootPrunesStaleAuditEvents(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
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

	if _, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE category='stale-probe'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stale audit row survived boot: n=%d err=%v", n, err)
	}
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE category='recent-probe'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("recent audit row lost at boot: n=%d err=%v", n, err)
	}
}
