package relay

import (
	"sync"
	"time"
)

// sessionRegistry owns the relay's live transport-session state: the
// leaseID -> live session map, the pending reconnect-expiry timers, and
// the single mutex guarding both. One lock covers both maps so generation
// checks, session replacement, and timer identity checks stay atomic
// against each other (P0-03, P1-03). No file outside relay_sessions.go
// touches these fields; every other layer goes through the Server
// methods (registerSession, evictLease, evictIfOlder, detach, armExpiry,
// liveSession), which keep durable state authoritative in SQLite.
//
// Nonces are deliberately NOT here: the challenge/handshake replay cache
// (relay_nonce.go) is its own lock domain. The two locks are never held
// at the same time, so no lock ordering exists to violate.
type sessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*Session    // leaseID -> live session
	timers   map[string]*time.Timer // leaseID -> pending expiry timer
}

func newSessionRegistry() sessionRegistry {
	return sessionRegistry{
		sessions: map[string]*Session{},
		timers:   map[string]*time.Timer{},
	}
}
