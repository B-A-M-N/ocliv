package cli

// P1: `ocliv relay issue-enroll --tenant NAME` must HONOR the operator's
// explicit tenant. The space form (`--tenant NAME`) was silently ignored
// by the flag scanner, so the enrollment code was bound to a freshly
// invented tenant namespace ("tenant-enr-<id>") instead of the tenant the
// operator named. A publisher enrolled under the wrong tenant lands in the
// wrong administrative scope, which is a security-relevant misrouting, not
// a cosmetic parsing issue.
//
// The invariant these tests pin: an explicit --tenant argument is either
// honored exactly, or the command REFUSES (exit 2, no code minted). It is
// never silently ignored.
import (
	"os"
	"path/filepath"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/store"
)

// enrollmentTenants returns the tenant bindings of every enrollment code
// in the store at dir.
func enrollmentTenants(t *testing.T, dir string) []string {
	t.Helper()
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	rows, err := db.SQL().Query(`SELECT tenant_id FROM enrollment_codes ORDER BY id`)
	if err != nil {
		t.Fatalf("query enrollment codes: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, tenant)
	}
	return out
}

// TestIssueEnrollHonorsExplicitTenant pins the space form: the minted code
// must be bound to the named tenant.
func TestIssueEnrollHonorsExplicitTenant(t *testing.T) {
	dir := t.TempDir()
	if code := cmdRelay([]string{"issue-enroll", "--tenant", "acme", "--data", dir}); code != 0 {
		t.Fatalf("issue-enroll --tenant acme: exit=%d", code)
	}
	tenants := enrollmentTenants(t, dir)
	if len(tenants) != 1 {
		t.Fatalf("want exactly one enrollment code, got %v", tenants)
	}
	if tenants[0] != "acme" {
		t.Fatalf("enrollment bound to tenant %q, want %q (the explicit --tenant was ignored)", tenants[0], "acme")
	}
}

// TestIssueEnrollEqualsTenantFormStillHonored keeps the equals form
// working: both spellings must reach the same binding.
func TestIssueEnrollEqualsTenantFormStillHonored(t *testing.T) {
	dir := t.TempDir()
	if code := cmdRelay([]string{"issue-enroll", "--tenant=acme", "--data", dir}); code != 0 {
		t.Fatalf("issue-enroll --tenant=acme: exit=%d", code)
	}
	tenants := enrollmentTenants(t, dir)
	if len(tenants) != 1 || tenants[0] != "acme" {
		t.Fatalf("equals form bound to %v, want [acme]", tenants)
	}
}

// TestIssueEnrollRejectsEmptyTenant pins the refusal half of the
// invariant: `--tenant=` with an empty value is an explicit but invalid
// request. It must fail closed (exit 2) rather than silently mint a code
// in an invented tenant namespace.
func TestIssueEnrollRejectsEmptyTenant(t *testing.T) {
	dir := t.TempDir()
	if code := cmdRelay([]string{"issue-enroll", "--tenant=", "--data", dir}); code == 0 {
		t.Fatal("issue-enroll --tenant= exited 0; an explicit empty tenant must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "ocliv.db")); !os.IsNotExist(err) {
		// The store may exist (the refusal happens after open), but no
		// enrollment code may have been minted.
		t.Logf("store exists after refusal (acceptable): %v", err)
	}
	if tenants := enrollmentTenants(t, dir); len(tenants) != 0 {
		t.Fatalf("a code was minted for an invalid tenant: %v", tenants)
	}
}

// TestIssueEnrollRejectsMissingTenantValue pins that `--tenant` with no
// value at all is refused instead of consuming the next flag (or nothing)
// and minting a code in an invented namespace.
func TestIssueEnrollRejectsMissingTenantValue(t *testing.T) {
	dir := t.TempDir()
	if code := cmdRelay([]string{"issue-enroll", "--tenant", "--data", dir}); code == 0 {
		t.Fatal("issue-enroll --tenant (no value) exited 0; it must be refused")
	}
	if tenants := enrollmentTenants(t, dir); len(tenants) != 0 {
		t.Fatalf("a code was minted for a missing tenant value: %v", tenants)
	}
}

// TestIssueEnrollWithoutTenantUsesDefaultSingleOperatorTenant verifies
// that with no --tenant and no active tenant yet, IssueEnrollmentCode binds
// to the single-operator "default" tenant instead of minting a random one.
func TestIssueEnrollWithoutTenantUsesDefaultSingleOperatorTenant(t *testing.T) {
	dir := t.TempDir()
	if code := cmdRelay([]string{"issue-enroll", "--data", dir}); code != 0 {
		t.Fatalf("issue-enroll (no tenant): exit=%d", code)
	}
	tenants := enrollmentTenants(t, dir)
	if len(tenants) != 1 {
		t.Fatalf("want one enrollment code, got %v", tenants)
	}
	if tenants[0] != "default" {
		t.Fatalf("no-tenant enrollment bound to %q, want \"default\"", tenants[0])
	}
}
