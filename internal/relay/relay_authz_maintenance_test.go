package relay

// F: expired authorization state must be reclaimed while the relay runs,
// not only at startup reconciliation. A continuously-running relay would
// otherwise accumulate consumed codes and consent challenges forever.

import (
	"context"
	"testing"
	"time"

	"ocliv/internal/authz"
)

func TestAuthzMaintenanceRunsPeriodically(t *testing.T) {
	// Drive the production loop on a short cadence: same code path,
	// shorter ticker.
	old := authzMaintenanceInterval
	authzMaintenanceInterval = 5 * time.Millisecond
	defer func() { authzMaintenanceInterval = old }()

	s, db := newMCPServer(t)
	az := authz.NewSQLStore(db.SQL())

	// Expired durable state that pruning must reclaim.
	if err := az.CreateCode(authz.Code{
		Code: "c-expired", ClientID: "cli-1", Tenant: "tenant-test", Route: "r-m",
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := az.CreateConsent(authz.Consent{
		Challenge: "cns-expired", ClientID: "cli-1", Tenant: "tenant-test", Route: "r-m",
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	// An abandoned client registration (never approved, past the
	// pending lifetime). TryRegisterClient honors the caller's
	// CreatedAt so the row lands backdated, as a genuinely old
	// registration would.
	if err := az.TryRegisterClient(authz.Client{
		ID: "cli-abandoned", Tenant: "tenant-test", Route: "r-m",
		CreatedAt: time.Now().Add(-(authz.MaxPendingClientAge + time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}
	// An abandoned but FRESH registration must survive.
	if err := az.TryRegisterClient(authz.Client{
		ID: "cli-fresh", Tenant: "tenant-test", Route: "r-m", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	// A live consent must survive pruning.
	if err := az.CreateConsent(authz.Consent{
		Challenge: "cns-live", ClientID: "cli-1", Tenant: "tenant-test", Route: "r-m",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunAuthzMaintenance(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var codes, consents int
		_ = db.SQL().QueryRow(`SELECT COUNT(1) FROM authz_codes`).Scan(&codes)
		_ = db.SQL().QueryRow(`SELECT COUNT(1) FROM authz_consent`).Scan(&consents)
		_, cerr := az.GetClient("cli-abandoned")
		if codes == 0 && consents == 1 && cerr != nil {
			break // reclaimed exactly the expired/abandoned rows
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("maintenance did not reclaim: codes=%d consents=%d abandonedErr=%v", codes, consents, cerr)
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance loop did not stop on context cancel")
	}
	// The live rows survived.
	if _, err := az.GetClient("cli-fresh"); err != nil {
		t.Fatalf("fresh registration was reclaimed: %v", err)
	}
	if _, err := az.ConsumeConsent("cns-live"); err != nil {
		t.Fatalf("live consent challenge was reclaimed: %v", err)
	}
}
