package relay

// Server-side tenant policy enforcement tests (P0/P1).
// These call insertLease and allocateNamed directly — no CLI involved —
// to prove the relay itself enforces policy regardless of what a publisher
// sends.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/store"
)

func newPolicyServer(t *testing.T) (*Server, *store.DB, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	// Insert a tenant and a key directly — no enrollment flow needed for unit tests.
	if _, err := db.SQL().Exec(
		`INSERT INTO tenants(id, status, created_at, quotas_json) VALUES('policy-tenant','active','2026-01-01T00:00:00Z','{}')`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(
		`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES('key-policy','policy-tenant',zeroblob(32),'active','2026-01-01T00:00:00Z')`,
	); err != nil {
		t.Fatal(err)
	}
	return s, db, "policy-tenant"
}

// TestPublicLeaseDefaultPolicyDenied proves that a public lease attempt
// fails when the tenant has the default policy (allow_public=false).
func TestPublicLeaseDefaultPolicyDenied(t *testing.T) {
	s, _, _ := newPolicyServer(t)
	intent := LeaseIntent{Port: 3000, Public: true, AccessMode: "public", Version: "1"}
	_, _, err := s.insertLease("policy-tenant", "key-policy", "testlabel", intent, time.Now(), nil)
	if err == nil {
		t.Fatal("expected error for public lease with default policy, got nil")
	}
	if !contains(err.Error(), "policy denies") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPublicLeaseAllowedAfterPolicySet proves that after setting allow_public=true
// the same lease creation succeeds.
func TestPublicLeaseAllowedAfterPolicySet(t *testing.T) {
	s, db, tenantID := newPolicyServer(t)
	if err := db.SetTenantPolicy(tenantID, store.TenantPolicy{AllowPublic: true}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	intent := LeaseIntent{Port: 3000, Public: true, AccessMode: "public", Version: "1"}
	_, _, err := s.insertLease(tenantID, "key-policy", "testlabel2", intent, time.Now(), nil)
	if err != nil {
		t.Fatalf("expected success after allow_public=true, got: %v", err)
	}
}

// TestMaxActiveLeasesEnforced proves that attempting to create more leases
// than MaxActiveLeases returns a quota error.
func TestMaxActiveLeasesEnforced(t *testing.T) {
	s, db, tenantID := newPolicyServer(t)
	if err := db.SetTenantPolicy(tenantID, store.TenantPolicy{AllowPublic: true, MaxActiveLeases: 2}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	intent := func(label string) LeaseIntent {
		return LeaseIntent{Port: 3000, Public: true, AccessMode: "public", Version: "1"}
	}
	// First two should succeed.
	if _, _, err := s.insertLease(tenantID, "key-policy", "lease-a", intent("lease-a"), time.Now(), nil); err != nil {
		t.Fatalf("lease 1 failed: %v", err)
	}
	if _, _, err := s.insertLease(tenantID, "key-policy", "lease-b", intent("lease-b"), time.Now(), nil); err != nil {
		t.Fatalf("lease 2 failed: %v", err)
	}
	// Third must fail with quota error.
	_, _, err := s.insertLease(tenantID, "key-policy", "lease-c", intent("lease-c"), time.Now(), nil)
	if err == nil {
		t.Fatal("expected quota error for 3rd lease, got nil")
	}
	if !contains(err.Error(), "limit reached") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestMaxPersistentLeasesEnforced proves that the persistent lease quota
// is enforced server-side via allocateNamed.
func TestMaxPersistentLeasesEnforced(t *testing.T) {
	s, db, tenantID := newPolicyServer(t)
	if err := db.SetTenantPolicy(tenantID, store.TenantPolicy{MaxPersistentLeases: 1}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	now := time.Now()
	intent1 := LeaseIntent{Port: 3000, Name: "svc-one", Persistent: true, Version: "1"}
	if _, _, err := s.allocateNamed(tenantID, "key-policy", intent1, now); err != nil {
		t.Fatalf("first named lease failed: %v", err)
	}
	intent2 := LeaseIntent{Port: 3000, Name: "svc-two", Persistent: true, Version: "1"}
	_, _, err := s.allocateNamed(tenantID, "key-policy", intent2, now)
	if err == nil {
		t.Fatal("expected persistent lease quota error, got nil")
	}
	if !contains(err.Error(), "limit reached") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDefaultPolicyAllowsProtectedLeases proves protected (non-public)
// leases work with the default policy (allow_public=false only gates public).
func TestDefaultPolicyAllowsProtectedLeases(t *testing.T) {
	s, _, tenantID := newPolicyServer(t)
	intent := LeaseIntent{Port: 3000, Public: false, Version: "1"}
	_, _, err := s.insertLease(tenantID, "key-policy", "protected-label", intent, time.Now(), nil)
	if err != nil {
		t.Fatalf("protected lease with default policy should succeed, got: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || containsSub(s, sub))
}

func containsSub(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
