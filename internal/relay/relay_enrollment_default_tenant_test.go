package relay

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ocliv/internal/store"
)

// TestResolveEnrollmentTenant covers the multi-tenant selection rules:
//
//	0 active tenants  → "default"
//	1 active tenant   → that tenant (optional convenience)
//	>1 active tenants → error requiring explicit --tenant
//	explicit tenant   → returned as-is
//	suspended tenant  → error (suspension check is in IssueEnrollmentCode)
func TestResolveEnrollmentTenant(t *testing.T) {
	openDB := func() *store.DB {
		db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}

	t.Run("zero tenants returns default", func(t *testing.T) {
		db := openDB()
		got, err := resolveEnrollmentTenant(db, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "default" {
			t.Fatalf("got %q, want default", got)
		}
	})

	t.Run("one active tenant returns that tenant", func(t *testing.T) {
		db := openDB()
		if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('tenant-a', 'active', '2026-01-01T00:00:00Z')`); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := resolveEnrollmentTenant(db, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "tenant-a" {
			t.Fatalf("got %q, want tenant-a", got)
		}
	})

	t.Run("two active tenants require explicit tenant", func(t *testing.T) {
		db := openDB()
		for _, id := range []string{"tenant-x", "tenant-y"} {
			if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES(?, 'active', '2026-01-01T00:00:00Z')`, id); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
		_, err := resolveEnrollmentTenant(db, "")
		if err == nil {
			t.Fatal("expected error for multiple active tenants, got nil")
		}
		if !strings.Contains(err.Error(), "--tenant is required") {
			t.Fatalf("error %q does not mention --tenant", err.Error())
		}
	})

	t.Run("explicit tenant returned as-is", func(t *testing.T) {
		db := openDB()
		for _, id := range []string{"tenant-1", "tenant-2"} {
			if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES(?, 'active', '2026-01-01T00:00:00Z')`, id); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
		got, err := resolveEnrollmentTenant(db, "tenant-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "tenant-1" {
			t.Fatalf("got %q, want tenant-1", got)
		}
	})

	t.Run("suspended tenant blocked by IssueEnrollmentCode", func(t *testing.T) {
		db := openDB()
		if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('tenant-susp', 'suspended', '2026-01-01T00:00:00Z')`); err != nil {
			t.Fatalf("insert: %v", err)
		}
		_, err := IssueEnrollmentCode(db, "tenant-susp", time.Hour, "operator")
		if err == nil {
			t.Fatal("expected error for suspended tenant, got nil")
		}
		if !strings.Contains(err.Error(), "suspended") {
			t.Fatalf("error %q does not mention suspended", err.Error())
		}
	})
}

// TestIssueEnrollmentCodeMultiTenant verifies that IssueEnrollmentCode
// uses resolveEnrollmentTenant and therefore fails on ambiguous selection.
func TestIssueEnrollmentCodeMultiTenant(t *testing.T) {
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

	// Add one active tenant -> reuses it without --tenant.
	if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('tenant-only', 'active', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := IssueEnrollmentCode(db, "", time.Hour, "operator"); err != nil {
		t.Fatalf("IssueEnrollmentCode single-tenant: %v", err)
	}
	var count int
	if err := db.SQL().QueryRow(`SELECT COUNT(1) FROM enrollment_codes WHERE tenant_id='tenant-only'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected single active tenant to be used, count=%d", count)
	}

	// Add a second active tenant -> ambiguous, must require explicit --tenant.
	if _, err := db.SQL().Exec(`INSERT INTO tenants(id, status, created_at) VALUES('tenant-other', 'active', '2026-02-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert second tenant: %v", err)
	}
	_, merr := IssueEnrollmentCode(db, "", time.Hour, "operator")
	if merr == nil {
		t.Fatal("expected error for two active tenants, got nil")
	}
	if !strings.Contains(merr.Error(), "--tenant is required") {
		t.Fatalf("error %q does not mention --tenant", merr.Error())
	}
	// With explicit tenant it should work.
	if _, err := IssueEnrollmentCode(db, "tenant-only", time.Hour, "operator"); err != nil {
		t.Fatalf("IssueEnrollmentCode explicit tenant: %v", err)
	}
}
