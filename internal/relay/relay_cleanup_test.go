package relay

// Session-cleanup lock-boundary tests (adversarial Finding 4).
// Yamux.Close() waits for session-loop teardown, which depends on the
// underlying conn's Close — here a websocket NetConn whose Close runs a
// peer-awaited close handshake. Against a dead peer that handshake hangs,
// so any registry-mutex critical section spanning Yamux.Close() stalls
// unrelated leases' registration, eviction, and route lookups.
//
// Both tests fail on the pre-fix behavior (Close under registry.mu) and
// pass when cleanup removes the entry under the lock and closes outside
// it — without ever evicting a newer generation's replacement.

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// hangingCloseConn simulates the adverse condition: the transport Close
// (e.g. a close handshake awaiting a dead peer) does not return until the
// test releases it. Reads/writes behave like the embedded conn.
type hangingCloseConn struct {
	net.Conn
	release chan struct{}
}

func (c *hangingCloseConn) Close() error {
	<-c.release
	return c.Conn.Close()
}

// stuckYamux returns a live yamux client session whose Close blocks until
// release is closed, plus a cleanup that always unblocks it.
func stuckYamux(t *testing.T) (*yamux.Session, chan struct{}, func()) {
	t.Helper()
	cli, srv := net.Pipe()
	release := make(chan struct{})
	ys, err := yamux.Client(&hangingCloseConn{Conn: cli, release: release}, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return ys, release, func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = srv.Close()
	}
}

// liveYamux returns a healthy session pair; the far end stays open so the
// session never reads closed.
func liveYamux(t *testing.T) (*yamux.Session, func()) {
	t.Helper()
	cli, srv := net.Pipe()
	ys, err := yamux.Client(cli, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return ys, func() {
		_ = ys.Close()
		_ = srv.Close()
	}
}

func insertRegistrySession(s *Server, sess *Session) {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	s.registry.sessions[sess.LeaseID] = sess
}

// TestBlockedSessionCloseDoesNotBlockUnrelatedLease: evicting a lease
// whose transport Close hangs must not stall route lookups for an
// unrelated lease. Pre-fix, evictLease holds registry.mu across
// Yamux.Close, so liveSession("healthy") blocks until the stuck close
// releases.
func TestBlockedSessionCloseDoesNotBlockUnrelatedLease(t *testing.T) {
	s, _ := newLifecycleServer(t)

	stuck, release, cleanup := stuckYamux(t)
	defer cleanup()
	insertRegistrySession(s, &Session{LeaseID: "stuck", Generation: 1, Yamux: stuck, closed: make(chan struct{})})

	healthy, healthyCleanup := liveYamux(t)
	defer healthyCleanup()
	insertRegistrySession(s, &Session{LeaseID: "healthy", Generation: 1, Yamux: healthy, closed: make(chan struct{})})

	evictDone := make(chan struct{})
	go func() {
		defer close(evictDone)
		s.evictLease("stuck")
	}()
	// Let the eviction reach the hanging Close.
	time.Sleep(300 * time.Millisecond)

	lookupDone := make(chan bool, 1)
	go func() {
		_, ok := s.liveSession("healthy")
		lookupDone <- ok
	}()
	select {
	case ok := <-lookupDone:
		if !ok {
			t.Fatal("healthy lease lost its route during unrelated eviction")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("route lookup for unrelated lease stalled behind hanging transport Close")
	}
	close(release)
	select {
	case <-evictDone:
	case <-time.After(5 * time.Second):
		t.Fatal("eviction never finished after transport Close released")
	}
}

// TestDelayedCleanupCannotEvictReplacement: the entry must be removed
// under the lock with cleanup outside it, and a replacement registered
// while cleanup is in flight must survive. Pre-fix, the replacement
// insert blocks on the held mutex (red via timeout); a naive
// delete-after-close fix would remove the replacement (red via mismatch).
func TestDelayedCleanupCannotEvictReplacement(t *testing.T) {
	s, _ := newLifecycleServer(t)

	stuck, release, cleanup := stuckYamux(t)
	defer cleanup()
	insertRegistrySession(s, &Session{LeaseID: "x", Generation: 1, Yamux: stuck, closed: make(chan struct{})})

	evictDone := make(chan struct{})
	go func() {
		defer close(evictDone)
		s.evictIfOlder("x", 2)
	}()

	// Wait until the eviction is in flight AND the mutex is free — i.e.
	// the hanging Close happens outside the critical section. Pre-fix
	// the mutex never frees while the eviction is stuck.
	replacementWindow := false
	for i := 0; i < 50; i++ {
		time.Sleep(50 * time.Millisecond)
		select {
		case <-evictDone:
			t.Fatal("eviction finished before replacement registered")
		default:
		}
		if s.registry.mu.TryLock() {
			s.registry.mu.Unlock()
			replacementWindow = true
			break
		}
	}
	if !replacementWindow {
		t.Fatal("registry mutex held for the whole stuck close: cleanup runs inside the critical section")
	}

	// Register the newer generation while old cleanup is still hanging.
	repl, replCleanup := liveYamux(t)
	defer replCleanup()
	insertRegistrySession(s, &Session{LeaseID: "x", Generation: 2, Yamux: repl, closed: make(chan struct{})})

	close(release)
	select {
	case <-evictDone:
	case <-time.After(5 * time.Second):
		t.Fatal("eviction never finished after transport Close released")
	}
	cur, ok := s.liveSession("x")
	if !ok {
		t.Fatal("replacement generation lost its route to delayed cleanup")
	}
	if cur.Generation != 2 {
		t.Fatalf("route owned by generation %d, want 2", cur.Generation)
	}
}
