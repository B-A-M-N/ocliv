package relay

import (
	"sync"
	"time"

	"ocliv/internal/limits"
	"ocliv/internal/metrics"
)

// nonceCache owns the challenge/handshake replay cache: nonce -> expiry.
// It is the only holder of this map and mutex. The session registry
// (relay_registry.go) is a separate lock domain; the two locks are never
// held at the same time, so no lock ordering exists to violate.
//
// Semantics preserved from the inline Server implementation:
//   - reserve sweeps expired entries, then fails closed when the table is
//     full (challenge floods cannot grow the map, G08).
//   - consume deletes exactly once: a replayed nonce is rejected (B07).
type nonceCache struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newNonceCache() nonceCache {
	return nonceCache{m: map[string]time.Time{}}
}

// reserve records nonce with expiry. It reports false when the table is
// full after sweeping expired entries.
func (c *nonceCache) reserve(nonce string, exp time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for n, e := range c.m {
		if now.After(e) {
			delete(c.m, n)
		}
	}
	if len(c.m) >= limits.MaxNonceEntries {
		return false
	}
	c.m[nonce] = exp
	metrics.Global.NonceEntries.Store(int64(len(c.m)))
	return true
}

// size reports the table cardinality for tests and metrics.
func (c *nonceCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// consume deletes nonce and reports its expiry. A missing nonce (never
// issued or already consumed) reports false.
func (c *nonceCache) consume(nonce string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[nonce]
	if ok {
		delete(c.m, nonce)
		metrics.Global.NonceEntries.Store(int64(len(c.m)))
	}
	return exp, ok
}
