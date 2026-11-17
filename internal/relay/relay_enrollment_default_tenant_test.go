package relay

import (
	"path/filepath"
	"testing"
	"time"

	"ocliv/internal/store"
)

func TestIssueEnrollmentCodeReusesActiveTenantOrDefault(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Empty DB -> "default"
	if _, err := IssueEnrollmentCode(db, "", time.Hour, "operator"); err != nil {
		t.Fatalf("IssueEnrollmentCode 1: %v", err)
	}
	var got string
	if err := db.SQL().QueryRow(`SELECT tenant_id FROM enrollment_codes LIMIT 1`).Scan(&got); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got != "default" {
		t.Fatalf("first tenant=%q, want default", got)
	}

	// Active tenant exists -> reuses existing active tenant
	if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('tenant-existing', 'active', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := IssueEnrollmentCode(db, "", time.Hour, "operator"); err != nil {
		t.Fatalf("IssueEnrollmentCode 2: %v", err)
	}
	var count int
	if err := db.SQL().QueryRow(`SELECT COUNT(1) FROM enrollment_codes WHERE tenant_id='tenant-existing'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected existing active tenant to be reused, count=%d", count)
	}
}
