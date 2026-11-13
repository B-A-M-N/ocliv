package relay

// P1: a cross-key publication conflict must be TERMINAL and ACTIONABLE.
//
// The relay closes a denied attach with 4409 for apperr.CodeConflict. The
// agent classifies 4401 as terminal and everything else as retryable, so a
// cross-key reclaim denial produced an endless "reconnecting" loop with no
// way for the operator to learn what to do.
//
// The distinction that matters: an ALLOCATION race (two publishers racing
// for a fresh lease) is genuinely retryable, while an OWNERSHIP conflict
// (this name is held by another agent key in this tenant) can never succeed
// on retry — the second key must change its name, or the operator must
// transfer ownership.
//
// These tests pin the relay half of that split: the ownership denial must
// carry a DISTINCT error code, so the close code can differ from the
// retryable conflict, and the audit trail must name the conflict.
import (
	"testing"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/protocol"
)

// TestOwnershipConflictHasDistinctCode pins the code split: the ownership
// denial must NOT reuse the retryable conflict code.
func TestOwnershipConflictHasDistinctCode(t *testing.T) {
	if apperr.CodeOwnershipConflict == apperr.CodeConflict {
		t.Fatal("ownership conflict shares the retryable conflict code; the agent cannot distinguish them")
	}
	if apperr.CodeOwnershipConflict == "" {
		t.Fatal("ownership conflict has no code of its own")
	}
}

// TestNamedReclaimCrossKeyDeniedAsOwnership: reclaiming a hostname held by
// another agent key in the same tenant must be refused with the OWNERSHIP
// code (terminal), not the generic conflict code (retryable).
func TestNamedReclaimCrossKeyDeniedAsOwnership(t *testing.T) {
	s, db := newLifecycleServer(t)
	insertLeaseRow(t, db, "lse-owner", "ACTIVE", 1, nil)
	if _, err := db.SQL().Exec(`UPDATE leases SET hostname=?, label=?, agent_key_id=? WHERE id=?`,
		"nm.t.example.test", "nm", "key-owner", "lse-owner"); err != nil {
		t.Fatal(err)
	}
	label := "nm"
	_, _, err := s.insertLease("tenant-test", "key-other", label,
		LeaseIntent{Port: 3000}, time.Now().UTC(), &label)
	if err == nil {
		t.Fatal("a foreign agent key reclaimed a held hostname")
	}
	var ae *apperr.Error
	if !asApperr(err, &ae) {
		t.Fatalf("denial is not a typed error: %v", err)
	}
	if ae.Code != apperr.CodeOwnershipConflict {
		t.Fatalf("cross-key denial code=%q, want %q (the agent treats the generic conflict as retryable)",
			ae.Code, apperr.CodeOwnershipConflict)
	}
	// The original lease keeps serving: the refusal is a refusal, not a
	// takeover and not a teardown.
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(1) FROM leases WHERE id='lse-owner'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("the refused reclaim disturbed the owning lease")
	}
}

// TestCrossTenantNameConflictIsOwnership: a name held by ANOTHER TENANT is
// equally terminal — retrying under the same tenant can never win it.
func TestCrossTenantNameConflictIsOwnership(t *testing.T) {
	s, db := newLifecycleServer(t)
	insertLeaseRow(t, db, "lse-other-tenant", "ACTIVE", 1, nil)
	if _, err := db.SQL().Exec(`UPDATE leases SET hostname=?, label=?, tenant_id=? WHERE id=?`,
		"nm.t.example.test", "nm", "tenant-other", "lse-other-tenant"); err != nil {
		t.Fatal(err)
	}
	label := "nm"
	_, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000}, time.Now().UTC(), &label)
	if err == nil {
		t.Fatal("a name held by another tenant was reclaimed")
	}
	var ae *apperr.Error
	if !asApperr(err, &ae) {
		t.Fatalf("denial is not a typed error: %v", err)
	}
	if ae.Code != apperr.CodeOwnershipConflict {
		t.Fatalf("cross-tenant denial code=%q, want %q", ae.Code, apperr.CodeOwnershipConflict)
	}
}

// TestOwnershipCloseCodeIsDistinctFromConflict pins the wire contract: the
// relay must close an ownership denial with a DIFFERENT websocket code than
// the retryable conflict, so the agent can stop instead of looping.
func TestOwnershipCloseCodeIsDistinctFromConflict(t *testing.T) {
	if protocol.CloseCodeAttachOwnership == protocol.CloseCodeAttachConflict {
		t.Fatalf("ownership close code %d equals the retryable conflict code", protocol.CloseCodeAttachOwnership)
	}
	if protocol.CloseCodeAttachOwnership == protocol.CloseCodeAttachDenied {
		t.Fatalf("ownership close code %d equals the terminal denial code; it needs its own class",
			protocol.CloseCodeAttachOwnership)
	}
}

// TestAttachCloseCodeForError pins the relay's code mapping: an ownership
// denial maps to the ownership close code, while a plain conflict keeps
// the retryable one.
func TestAttachCloseCodeForError(t *testing.T) {
	own := apperr.E(apperr.CodeOwnershipConflict, "named host is held by another agent key in this tenant", nil)
	if got := attachCloseCode(own); got != protocol.CloseCodeAttachOwnership {
		t.Fatalf("ownership denial close code=%d, want %d", got, protocol.CloseCodeAttachOwnership)
	}
	race := apperr.E(apperr.CodeConflict, "concurrent resume superseded", nil)
	if got := attachCloseCode(race); got != protocol.CloseCodeAttachConflict {
		t.Fatalf("retryable conflict close code=%d, want %d", got, protocol.CloseCodeAttachConflict)
	}
}
