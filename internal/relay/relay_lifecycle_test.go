package relay

// Lifecycle synchronization regression tests (P0-03, P1-03, P1-05).
// Each fails on the pre-fix behavior: unconditional detach marking,
// deadline-blind expiry, ignored reconcile errors, unconditional
// registration overwrite.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"ocliv/internal/lease"
	"ocliv/internal/limits"
	"ocliv/internal/store"
)

func newLifecycleServer(t *testing.T) (*Server, *store.DB) {
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
	return s, db
}

func insertLeaseRow(t *testing.T, db *store.DB, id, status string, gen int, reconnectUntil *string) {
	t.Helper()
	var ru any
	if reconnectUntil != nil {
		ru = *reconnectUntil
	}
	_, err := db.SQL().Exec(
		`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, reconnect_until, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		id, "tenant-test", "key-test", "h-"+id, "label-"+id, 3000, "private", gen, status, ru,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
}

func leaseStatus(t *testing.T, db *store.DB, id string) (string, *string) {
	t.Helper()
	var state string
	var ru *string
	if err := db.SQL().QueryRow(`SELECT status, reconnect_until FROM leases WHERE id=?`,
		id).Scan(&state, &ru); err != nil {
		t.Fatal(err)
	}
	return state, ru
}

// TestDetachStaleKeepsActive: detaching a superseded/evicted session must
// not touch shared lifecycle state. Pre-fix, detach unconditionally marked
// RECONNECTING, letting a late disconnect downgrade a live ACTIVE lease.
// TestRevokeLeaseFailsClosed: a revocation that cannot commit reports an
// error instead of success. With a broken database every statement fails,
// so revokeLease must return an error and the caller must not acknowledge
// revocation (qualification P0: no false-success responses).
func TestRevokeLeaseFailsClosed(t *testing.T) {
	s, _ := newLimitServer(t)
	_ = s.db.Close()
	if err := s.revokeLease("lse-missing"); err == nil {
		t.Fatal("revokeLease succeeded against a broken database")
	}
}

func TestDetachStaleKeepsActive(t *testing.T) {
	s, db := newLifecycleServer(t)
	insertLeaseRow(t, db, "lse-stale", "ACTIVE", 7, nil)
	live := &Session{LeaseID: "lse-stale", Generation: 7, closed: make(chan struct{})}
	s.registry.mu.Lock()
	s.registry.sessions["lse-stale"] = live
	s.registry.mu.Unlock()

	stale := &Session{LeaseID: "lse-stale", Generation: 5, closed: make(chan struct{})}
	s.detach(stale, "lse-stale")

	state, ru := leaseStatus(t, db, "lse-stale")
	if state != "ACTIVE" {
		t.Fatalf("stale detach changed status to %q", state)
	}
	if ru != nil {
		t.Fatal("stale detach armed a reconnect window on a live lease")
	}
	s.registry.mu.Lock()
	cur := s.registry.sessions["lse-stale"]
	s.registry.mu.Unlock()
	if cur != live {
		t.Fatal("stale detach disturbed the live registry entry")
	}
}

// TestArmExpiryHonorsNewerDeadline: a timer armed for an elapsed window
// must not expire a lease whose persisted deadline was extended (P1-03).
// Pre-fix, any timer expired any RECONNECTING lease without a session.
func TestArmExpiryHonorsNewerDeadline(t *testing.T) {
	s, db := newLifecycleServer(t)
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	insertLeaseRow(t, db, "lse-window", "RECONNECTING", 2, &future)
	s.armExpiry("lse-window", time.Now().UTC().Add(-time.Second))
	time.Sleep(200 * time.Millisecond)
	if state, _ := leaseStatus(t, db, "lse-window"); state != "RECONNECTING" {
		t.Fatalf("stale timer expired a live window: %q", state)
	}

	past := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	insertLeaseRow(t, db, "lse-due", "RECONNECTING", 2, &past)
	s.armExpiry("lse-due", time.Now().UTC().Add(-time.Second))
	deadline := time.Now().Add(5 * time.Second)
	for {
		state, _ := leaseStatus(t, db, "lse-due")
		if state == "EXPIRED" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("elapsed window never expired")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReconcileBootFailureRefusesStartup: a dead store must refuse relay
// startup, not serve on unknown durable state (P1-05).
func TestReconcileBootFailureRefusesStartup(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"}); err == nil {
		t.Fatal("startup with a dead store accepted")
	}
}

// TestNamedReclaimRetiresOldSession: reclaiming a hostname must evict the
// previous live session and drop its budget. Pre-fix, insertLease deleted
// the rows but left the orphaned session and budget behind (P1-04).
func TestNamedReclaimRetiresOldSession(t *testing.T) {
	s, db := newLifecycleServer(t)
	insertLeaseRow(t, db, "lse-old", "ACTIVE", 3, nil)
	_, err := db.SQL().Exec(`UPDATE leases SET hostname=?, label=? WHERE id=?`,
		"nm.t.example.test", "nm", "lse-old")
	if err != nil {
		t.Fatal(err)
	}
	old := &Session{LeaseID: "lse-old", Generation: 3, closed: make(chan struct{})}
	s.registry.mu.Lock()
	s.registry.sessions["lse-old"] = old
	s.registry.mu.Unlock()
	_ = s.budgets.For("lse-old")

	label := "nm"
	ls, _, err := s.insertLease("tenant-test", "key-test", label,
		LeaseIntent{Port: 3000}, time.Now().UTC(), &label)
	if err != nil {
		t.Fatal(err)
	}
	if ls.ID == "lse-old" {
		t.Fatal("reclaim did not mint a replacement lease")
	}
	s.registry.mu.Lock()
	_, stillLive := s.registry.sessions["lse-old"]
	s.registry.mu.Unlock()
	if stillLive {
		t.Fatal("reclaimed lease still has a live session")
	}
	select {
	case <-old.closed:
	default:
		t.Fatal("old session was not closed by reclamation")
	}
}

// TestRegisterStaleGenerationRejected: registering an older generation
// over a newer live one must be refused without touching shared state.
// Pre-fix, the stale session overwrote the map and the test hangs on the
// (never-closed) session instead of returning.
func TestRegisterStaleGenerationRejected(t *testing.T) {
	s, _ := newLifecycleServer(t)
	const leaseID = "lse-reg"
	live := &Session{LeaseID: leaseID, Generation: 7, closed: make(chan struct{})}
	s.registry.mu.Lock()
	s.registry.sessions[leaseID] = live
	s.registry.mu.Unlock()

	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		<-r.Context().Done()
	}))
	defer ws.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, ws.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.registerSession(context.Background(), conn,
			&lease.Lease{ID: leaseID, Hostname: "h", Generation: 5, AccessMode: "private"},
			"tenant-test", "key-test", "")
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("stale registration was stored instead of rejected")
	}
	s.registry.mu.Lock()
	cur := s.registry.sessions[leaseID]
	s.registry.mu.Unlock()
	if cur != live {
		t.Fatal("stale registration overwrote the newer live session")
	}
}

// TestUnconfirmedNewLeaseRefused locks the F06 contract the agent's
// readiness probe relies on: a new-lease intent without confirmed local
// readiness is refused, never minted (P1-09).
func TestUnconfirmedNewLeaseRefused(t *testing.T) {
	s, _ := newLifecycleServer(t)
	_, _, err := s.allocateOrResume("tenant-test", "key-test", LeaseIntent{
		Port: 3000, Ready: false, Version: "1",
	})
	if err == nil {
		t.Fatal("unconfirmed new lease minted")
	}
	if got := err.Error(); !strings.Contains(got, "local readiness not confirmed") {
		t.Fatalf("unexpected error %q", got)
	}
}

// TestStaleDisconnectCannotDowngradeNewGeneration: a stale generation's
// disconnect transition must not overwrite a newer generation's ACTIVE
// row (adversarial Finding 1). Pre-fix, markReconnecting updated by id +
// status only, so a late gen-1 write flipped a resumed gen-2 ACTIVE row
// back to RECONNECTING and armed expiry against the live generation.
func TestStaleDisconnectCannotDowngradeNewGeneration(t *testing.T) {
	s, db := newLifecycleServer(t)
	insertLeaseRow(t, db, "lse-fence", string(lease.StateActive), 2, nil)

	// Stale generation loses: no row change, no expiry window set.
	won, err := s.markReconnecting("lse-fence", 1)
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("stale generation won the reconnect transition")
	}
	if st, ru := leaseStatus(t, db, "lse-fence"); st != string(lease.StateActive) || ru != nil {
		t.Fatalf("stale transition mutated row: status=%q reconnect_until=%v", st, ru)
	}

	// Current generation wins and arms a reconnect window.
	won, err = s.markReconnecting("lse-fence", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !won {
		t.Fatal("current generation lost its own reconnect transition")
	}
	if st, ru := leaseStatus(t, db, "lse-fence"); st != string(lease.StateReconnecting) || ru == nil {
		t.Fatalf("winning transition not recorded: status=%q reconnect_until=%v", st, ru)
	}

	// A second stale attempt after the win still loses.
	won, err = s.markReconnecting("lse-fence", 1)
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("stale generation won against a RECONNECTING row")
	}
	if st, _ := leaseStatus(t, db, "lse-fence"); st != string(lease.StateReconnecting) {
		t.Fatalf("stale transition changed status to %q", st)
	}
}

// TestMarkReconnectingPropagatesDBErrors: a failed transition is
// reported, never claimed as a successful reconnect-state change, so
// callers cannot arm expiry against unknown durable state.
func TestMarkReconnectingPropagatesDBErrors(t *testing.T) {
	s, _ := newLifecycleServer(t)
	_ = s.db.Close()
	if _, err := s.markReconnecting("lse-missing", 1); err == nil {
		t.Fatal("markReconnecting succeeded against a broken database")
	}
}

// TestReadyForSessionsReflectsPrerequisites (P2-2): /health/ready must
// report SQLite writability, initialized routing, and available
// capacity — not merely a TCP accept or Ping. A dead database fails the
// probe; a saturated admission map fails it too.
func TestReadyForSessionsReflectsPrerequisites(t *testing.T) {
	s, db := newLifecycleServer(t)
	if !s.ReadyForSessions() {
		t.Fatal("fresh server reports not ready")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if s.ReadyForSessions() {
		t.Fatal("server with dead database reports ready")
	}
}

func TestReadyForSessionsDeniesSaturatedAdmission(t *testing.T) {
	s, _ := newLifecycleServer(t)
	for i := 0; i < limits.MaxThrottleKeys+16; i++ {
		s.mcpAdmission.Allow("flood:10.9.9.9:" + strconv.Itoa(i))
	}
	if s.ReadyForSessions() {
		t.Fatal("server with saturated admission map reports ready")
	}
}
