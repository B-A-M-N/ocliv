// Live transport-session lifecycle (relay side): session registration,
// supervision, eviction, disconnect handling, and reconnect-expiry timers.
//
// This layer owns the live registry (sessionRegistry: sessions map,
// expiry timers map, and their mutex). No other file touches those fields
// directly. Durable state
// stays authoritative in the leases table (relay_leases.go); this layer
// records RECONNECTING and arms expiry, but never invents ACTIVE.
package relay

import (
	"context"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"ocliv/internal/lease"
	"ocliv/internal/metrics"
)

// registerSession bridges to yamux, publishes the live route (F06), and
// supervises disconnect -> RECONNECTING -> EXPIRED (F10, F11).
func (s *Server) registerSession(_ context.Context, conn *websocket.Conn, ls *lease.Lease, tenantID, keyID, _ string) {
	netConn := websocket.NetConn(context.Background(), conn, websocket.MessageBinary)
	ys, err := yamux.Client(netConn, yamux.DefaultConfig())
	if err != nil {
		conn.Close(1011, "yamux")
		if _, merr := s.markReconnecting(ls.ID, ls.Generation); merr != nil {
			s.db.Audit("system", "", ls.ID, "attach", "error", "reconnect transition failed: "+errShort(merr))
		}
		return
	}
	sess := &Session{
		LeaseID: ls.ID, TenantID: tenantID, KeyID: keyID,
		Hostname: ls.Hostname, Generation: ls.Generation, AccessMode: ls.AccessMode,
		Yamux: ys, Budget: s.budgets.For(ls.ID), LastSeen: time.Now(), closed: make(chan struct{}),
	}
	s.registry.mu.Lock()
	var retired *Session
	if old, ok := s.registry.sessions[ls.ID]; ok {
		if old.Generation >= sess.Generation {
			// Stale registration: a newer (or equal) generation already
			// owns the route. Close the latecomer without touching shared
			// state — it must not overwrite, evict, or re-mark anything.
			s.registry.mu.Unlock()
			sess.close()
			if sess.Yamux != nil {
				sess.Yamux.Close()
			}
			conn.Close(1011, "superseded")
			s.db.Audit("agent", tenantID, ls.ID, "attach", "denied", "stale generation registration")
			return
		}
		// Swap ownership atomically under the lock, but close the retired
		// transport outside it: Yamux.Close waits on loop teardown gated
		// by conn Close (a peer-awaited close handshake), which can hang
		// on a dead peer and must never stall unrelated leases (Finding 4).
		retired = old
		delete(s.registry.sessions, ls.ID)
	}
	s.registry.sessions[ls.ID] = sess
	s.registry.mu.Unlock()
	if retired != nil {
		retired.close()
		if retired.Yamux != nil {
			retired.Yamux.Close()
		}
	}
	s.db.Audit("agent", tenantID, ls.ID, "attach", "ok", "route active")
	// Heartbeat supervision: yamux keepalives flow on the session; if the
	// session dies we mark RECONNECTING and start the grace timer.
	go s.supervise(sess, ls.ID)
	<-sess.closed
}

// supervise waits for session death, marks RECONNECTING, and expires the
// ephemeral lease after the grace window (F04).
func (s *Server) supervise(sess *Session, leaseID string) {
	// Poll for session closure; yamux exposes IsClosed.
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-sess.closed:
			return
		case <-t.C:
			if sess.Yamux.IsClosed() {
				s.detach(sess, leaseID)
				return
			}
			// Bounded operator-revocation enforcement (P0-A): a
			// CLI-driven key/tenant revocation lands in durable
			// state without a running Server to evict sessions.
			// Revalidate the lease each tick so idle streams die
			// within one interval of terminal revocation instead
			// of forwarding until the next visitor request.
			var st string
			if err := s.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&st); err != nil {
				s.detach(sess, leaseID)
				s.evictLease(leaseID)
				return
			}
			if st == lease.StateRevoked || st == lease.StateClosed || st == lease.StateExpired {
				s.db.Audit("agent", "", leaseID, "supervise", "evicted", "lease terminal ("+st+") under live session")
				s.detach(sess, leaseID)
				s.evictLease(leaseID)
				return
			}
		}
	}
}

// evictLease terminates the live session for a lease, drops its budget,
// and forgets the session object. New requests fail closed at route();
// the agent re-establishes only through a fresh authorized resume, and
// visitors must re-authenticate (C10, F07, R4).
func (s *Server) evictLease(leaseID string) {
	// Remove the entry under the lock, close outside it: a hanging
	// transport Close must not stall unrelated leases (Finding 4). Route
	// lookups fail closed between removal and close, which is safe — the
	// session can no longer serve either way.
	s.registry.mu.Lock()
	sess, ok := s.registry.sessions[leaseID]
	if ok {
		delete(s.registry.sessions, leaseID)
	}
	s.registry.mu.Unlock()
	if ok {
		sess.close()
		if sess.Yamux != nil {
			sess.Yamux.Close()
		}
	}
	s.budgets.Drop(leaseID)
}

// evictIfOlder retires the registered session for leaseID when it is
// strictly older than newGen. The durable fence must win first: call only
// after the generation update commits, so a newer generation that
// registered meanwhile is never evicted by a stale winner (P0-03).
func (s *Server) evictIfOlder(leaseID string, newGen uint64) {
	// Snapshot and remove under the lock, close outside it (Finding 4).
	// The entry is gone before the transport closes, so a replacement
	// registered during a hanging close survives: there is no second
	// delete that could remove the newer generation.
	s.registry.mu.Lock()
	old, ok := s.registry.sessions[leaseID]
	retire := ok && old.Generation < newGen
	if retire {
		delete(s.registry.sessions, leaseID)
		metrics.Global.FencingRejects.Add(1)
	}
	s.registry.mu.Unlock()
	if retire {
		old.close()
		if old.Yamux != nil {
			old.Yamux.Close()
		}
	}
}

// detach removes the session, marks RECONNECTING, and arms expiry — but
// only when the detaching session still owns the registry entry. A stale
// disconnect (superseded generation, evicted session) must never downgrade
// shared lifecycle state (P0-03). The durable transition is additionally
// fenced on the detaching session's generation: a newer generation that
// resumed between the registry removal and this write stays ACTIVE, and
// the expiry timer is armed only for a transition this detach won
// (adversarial Finding 1).
func (s *Server) detach(sess *Session, leaseID string) {
	sess.close()
	s.registry.mu.Lock()
	cur, ok := s.registry.sessions[leaseID]
	if !ok || cur != sess {
		s.registry.mu.Unlock()
		return
	}
	delete(s.registry.sessions, leaseID)
	s.registry.mu.Unlock()
	won, err := s.markReconnecting(leaseID, sess.Generation)
	if err != nil {
		s.db.Audit("system", "", leaseID, "detach", "error", "reconnect transition failed: "+errShort(err))
		return
	}
	if !won {
		// A newer generation owns the row now; its own lifecycle
		// governs expiry. Arming here could only enforce a stale
		// window against the current generation (Finding 1).
		return
	}
	s.armExpiry(leaseID, time.Now().UTC().Add(lease.ReconnectGrace))
}

// armExpiry flips a RECONNECTING lease to EXPIRED at the given deadline
// unless a live session reappears first. Crash-safe: the deadline lives in
// the DB row, and reconcileBoot re-arms every survivor (AS-083).
// A stale timer can never kill a newer reconnect window: arming supersedes
// any previous timer, and the expiry itself requires the persisted deadline
// to still be elapsed (P1-03).
func (s *Server) armExpiry(leaseID string, at time.Time) {
	s.registry.mu.Lock()
	if old, ok := s.registry.timers[leaseID]; ok {
		old.Stop()
	}
	d := time.Until(at)
	if d < 0 {
		d = 0
	}
	var timer *time.Timer
	timer = time.AfterFunc(d, func() {
		s.registry.mu.Lock()
		if cur, ok := s.registry.timers[leaseID]; ok && cur == timer {
			delete(s.registry.timers, leaseID)
		}
		_, live := s.registry.sessions[leaseID]
		s.registry.mu.Unlock()
		if live {
			return
		}
		res, err := s.db.SQL().Exec(
			`UPDATE leases SET status=? WHERE id=? AND status=?
			 AND reconnect_until IS NOT NULL AND reconnect_until <= ?`,
			lease.StateExpired, leaseID, lease.StateReconnecting,
			time.Now().UTC().Format(time.RFC3339Nano))
		if err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				s.budgets.Drop(leaseID)
				s.db.Audit("system", "", leaseID, "lease_expire", "ok", "reconnect grace elapsed")
			}
		}
	})
	s.registry.timers[leaseID] = timer
	s.registry.mu.Unlock()
}

// markReconnecting records RECONNECTING in the DB (recovery reads this,
// F11). The update is a generation-fenced compare-and-swap: only the row
// still owned by the given generation in ACTIVE state transitions. A
// stale disconnect racing a newer resume loses (returns false) instead of
// downgrading the current generation to RECONNECTING (adversarial
// Finding 1). Database errors propagate so a failed transition is never
// reported as a successful reconnect-state change.
func (s *Server) markReconnecting(leaseID string, generation uint64) (bool, error) {
	res, err := s.db.SQL().Exec(
		`UPDATE leases SET status=?, reconnect_until=? WHERE id=? AND generation=? AND status=?`,
		lease.StateReconnecting,
		time.Now().UTC().Add(lease.ReconnectGrace).Format(time.RFC3339Nano),
		leaseID, generation, lease.StateActive)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// liveSession returns the authoritative live session for a lease, if any.
func (s *Server) liveSession(leaseID string) (*Session, bool) {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	sess, ok := s.registry.sessions[leaseID]
	if !ok || sess.Yamux.IsClosed() {
		return nil, false
	}
	return sess, true
}
