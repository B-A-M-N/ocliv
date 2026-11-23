package relay

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/access"
)

// TestRevokeDuringUseDeniesAfterCommit: with dozens of in-flight visitor
// authorizations, a revocation that commits mid-flight must deny every
// authorization completing afterward. The consumption UPDATE re-asserts
// revocation atomically; a SELECT-then-UPDATE without that predicate lets
// pre-revoke reads authorize post-revoke requests (qualification P1).
//
// Each validation scans ~100 rows through the single serialized pool
// connection, so one call spans milliseconds: checks in flight when the
// revocation commits complete after it, inside the drain window below.
func TestRevokeDuringUseDeniesAfterCommit(t *testing.T) {
	s, _ := newLimitServer(t)
	const leaseID = "lse-race"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Parent lease row: foreign-key enforcement rejects orphan tokens.
	if _, err := s.db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		leaseID, "t1", "k1", "h1.t.example.test", "h1", 3000, "protected", 1, "ACTIVE", now); err != nil {
		t.Fatal(err)
	}
	// Padding rows widen each validation scan so in-flight checks overlap
	// the revocation commit.
	for i := 0; i < 100; i++ {
		tok, err := access.Mint("visitor")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.SQL().Exec(
			`INSERT INTO access_tokens(id, lease_id, verifier, scope, created_at, max_uses, uses)
			 VALUES(?,?,?,?,?,?,0)`,
			fmt.Sprintf("tok-pad-%d", i), leaseID, tok.Verifier, "visitor", now, 0); err != nil {
			t.Fatal(err)
		}
	}
	target, err := access.Mint("visitor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.SQL().Exec(
		`INSERT INTO access_tokens(id, lease_id, verifier, scope, created_at, max_uses, uses)
		 VALUES(?,?,?,?,?,?,0)`,
		"tok-target", leaseID, target.Verifier, "visitor", now, 0); err != nil {
		t.Fatal(err)
	}
	tgt := &routeTarget{LeaseID: leaseID}

	var preOK atomic.Int64
	var totalOK atomic.Int64
	var revokeCommitted atomic.Bool
	var postRevokeOK atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				startedAfter := revokeCommitted.Load()
				if !s.checkVisitorToken(tgt, target.Raw) {
					continue
				}
				totalOK.Add(1)
				if startedAfter {
					postRevokeOK.Add(1)
				} else if !revokeCommitted.Load() {
					preOK.Add(1)
				}
			}
		}()
	}
	// Wait for steady pre-revoke traffic so the race is exercised no
	// matter how slow the machine is.
	ready := time.Now().Add(30 * time.Second)
	for preOK.Load() < 20 && time.Now().Before(ready) {
		time.Sleep(10 * time.Millisecond)
	}
	tx, err := s.db.SQL().Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		`UPDATE access_tokens SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), leaseID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	var usesAtRevoke int64
	if err := tx.QueryRow(`SELECT uses FROM access_tokens WHERE id='tok-target'`).Scan(&usesAtRevoke); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	revokeCommitted.Store(true)
	wg.Wait()
	if preOK.Load() < 20 {
		t.Fatalf("only %d pre-revoke authorizations; race never exercised", preOK.Load())
	}
	if got := postRevokeOK.Load(); got != 0 {
		t.Fatalf("%d authorizations started after revocation committed succeeded", got)
	}
	var finalUses int64
	if err := s.db.SQL().QueryRow(`SELECT uses FROM access_tokens WHERE id='tok-target'`).Scan(&finalUses); err != nil {
		t.Fatal(err)
	}
	if finalUses != usesAtRevoke || finalUses != totalOK.Load() {
		t.Fatalf("linearizability violation: finalUses=%d usesAtRevoke=%d totalOK=%d", finalUses, usesAtRevoke, totalOK.Load())
	}
}
