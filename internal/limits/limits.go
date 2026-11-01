// Package limits owns resource governance: header/body/stream caps, per-lease
// concurrency budgets, and rate limiting (G01-G06). Admission control runs
// BEFORE expensive stream creation or local dials (G02).
package limits

import (
	"sync"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/metrics"
)

// Defaults per spec section 6; operator-adjustable down or up within a cap.
const (
	MaxHeaderBytes  = 32 * 1024
	MaxBufferedBody = 64 * 1024
	MaxBodyBytes    = int64(64 << 20)
	MaxStreamsLease = 64
	MaxWSLease      = 32
	HeaderTimeout   = 10 * time.Second
	UpstreamTimeout = 3 * time.Second
	WSMaxLifetime   = 6 * time.Hour
	WSIdleTimeout   = 5 * time.Minute
	MaxBurstReg     = 10 // registrations per minute per tenant
	// Hard cardinality caps: unique-key floods fail closed instead of
	// growing maps without bound (G08). Eviction keeps live use well
	// under these ceilings.
	MaxThrottleKeys = 4096
	MaxNonceEntries = 4096
	// PreAuthBurst caps pre-authentication requests per IP per minute
	// (challenge, enroll, unlock, redeem) against guessing and floods
	// (G07). Legitimate use stays far below this ceiling.
	PreAuthBurst = 1000
	// MCPAdmissionBurst caps MCP-profile requests per (source, lease)
	// per minute before forwarding (P1-10). MCP profiles bypass Ocliv
	// visitor authentication, so without this an unauthenticated flood
	// could consume stream slots and upstream capacity even when the
	// upstream OAuth server ultimately denies it. Ordinary MCP use —
	// initialize, discovery, occasional tool calls — stays far below.
	MCPAdmissionBurst = 120
)

// FirstByteTimeout bounds the wait for an upstream response head after
// the request upload completes. It is a var (not const) so integration
// tests can shrink the deadline deterministically; production code never
// mutates it. Reader: relay_http, relay_ws, agent local dial.
var FirstByteTimeout = 30 * time.Second

// LeaseBudget tracks live stream counts for one lease.
type LeaseBudget struct {
	mu      sync.Mutex
	streams int
	ws      int
}

// TryAcquire reserves one stream slot, or rejects deterministically (G05).
func (b *LeaseBudget) TryAcquire(isWS bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.streams >= MaxStreamsLease {
		return apperr.E(apperr.CodeCapacity, "per-lease stream quota exceeded", nil)
	}
	if isWS && b.ws >= MaxWSLease {
		return apperr.E(apperr.CodeCapacity, "per-lease websocket quota exceeded", nil)
	}
	b.streams++
	if isWS {
		b.ws++
	}
	return nil
}

// Release frees a previously acquired slot. Always call on stream end (E06).
func (b *LeaseBudget) Release(isWS bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.streams > 0 {
		b.streams--
	}
	if isWS && b.ws > 0 {
		b.ws--
	}
}

// InFlight reports current usage for metrics.
func (b *LeaseBudget) InFlight() (streams, ws int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.streams, b.ws
}

// Registry tracks per-lease budgets with bounded cardinality (G08).
type Registry struct {
	mu      sync.Mutex
	budgets map[string]*LeaseBudget
}

// NewRegistry creates an empty budget registry.
func NewRegistry() *Registry { return &Registry{budgets: map[string]*LeaseBudget{}} }

// For returns the budget for a lease, creating it on first use.
func (r *Registry) For(leaseID string) *LeaseBudget {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.budgets[leaseID]
	if !ok {
		b = &LeaseBudget{}
		r.budgets[leaseID] = b
	}
	return b
}

// Drop removes a lease budget on lease closure.
func (r *Registry) Drop(leaseID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.budgets, leaseID)
}

// Throttle is a simple per-key token bucket for registration/auth attempts.
type Throttle struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

// NewThrottle builds a throttle allowing max events per window.
func NewThrottle(max int, window time.Duration) *Throttle {
	return &Throttle{hits: map[string][]time.Time{}, max: max, window: window}
}

// Allow reports whether key may proceed; denies before allocating state (G02).
// Idle keys are evicted and total cardinality is capped: a unique-key flood
// fails closed instead of growing the map without bound (G08).
func (t *Throttle) Allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	cut := now.Add(-t.window)
	if ts, ok := t.hits[key]; ok {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cut) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(t.hits, key)
		} else {
			t.hits[key] = kept
		}
	}
	if _, ok := t.hits[key]; !ok {
		if len(t.hits) >= MaxThrottleKeys {
			// Full: reclaim idle keys once before failing closed, so a
			// past flood cannot pin the limiter at capacity forever.
			t.sweepLocked(now)
			if len(t.hits) >= MaxThrottleKeys {
				return false
			}
		}
		t.hits[key] = []time.Time{now}
		metrics.Global.ThrottleKeys.Store(int64(len(t.hits)))
		return true
	}
	if len(t.hits[key]) >= t.max {
		return false
	}
	t.hits[key] = append(t.hits[key], now)
	return true
}

// sweepLocked drops every key whose hits are all outside the window.
func (t *Throttle) sweepLocked(now time.Time) {
	cut := now.Add(-t.window)
	for k, ts := range t.hits {
		keep := false
		for _, t := range ts {
			if t.After(cut) {
				keep = true
				break
			}
		}
		if !keep {
			delete(t.hits, k)
		}
	}
	metrics.Global.ThrottleKeys.Store(int64(len(t.hits)))
}

// Keys reports current map cardinality (for observability tests).
func (t *Throttle) Keys() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.hits)
}
