package limits

import "sync/atomic"

// DefaultGlobalMaxHTTPStreams is the default aggregate HTTP stream cap across
// all leases. Each lease can still use up to MaxStreamsLease streams; this
// caps the total across all concurrent leases.
const (
	DefaultGlobalMaxHTTPStreams = 4096
	DefaultGlobalMaxWSStreams   = 1024
	DefaultGlobalMaxSessions    = 512
)

// GlobalBudget tracks server-wide resource totals across all leases.
// A zero max (<=0) means unlimited for that resource class.
type GlobalBudget struct {
	maxHTTPStreams int64
	maxWSStreams   int64
	maxSessions    int64
	activeHTTP     atomic.Int64
	activeWS       atomic.Int64
	activeSessions atomic.Int64
}

// NewGlobalBudget creates a governor with the given per-class limits.
// Pass 0 for any class to disable that limit.
func NewGlobalBudget(maxHTTP, maxWS, maxSessions int64) *GlobalBudget {
	return &GlobalBudget{
		maxHTTPStreams: maxHTTP,
		maxWSStreams:   maxWS,
		maxSessions:    maxSessions,
	}
}

// AdmitHTTP increments the global HTTP stream count if below the cap.
// Returns true when admitted; the caller must call ReleaseHTTP when done.
func (g *GlobalBudget) AdmitHTTP() bool {
	if g.maxHTTPStreams <= 0 {
		g.activeHTTP.Add(1)
		return true
	}
	for {
		cur := g.activeHTTP.Load()
		if cur >= g.maxHTTPStreams {
			return false
		}
		if g.activeHTTP.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// ReleaseHTTP decrements the global HTTP stream count.
func (g *GlobalBudget) ReleaseHTTP() { g.activeHTTP.Add(-1) }

// AdmitWS increments the global WebSocket stream count if below the cap.
func (g *GlobalBudget) AdmitWS() bool {
	if g.maxWSStreams <= 0 {
		g.activeWS.Add(1)
		return true
	}
	for {
		cur := g.activeWS.Load()
		if cur >= g.maxWSStreams {
			return false
		}
		if g.activeWS.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// ReleaseWS decrements the global WebSocket stream count.
func (g *GlobalBudget) ReleaseWS() { g.activeWS.Add(-1) }

// AdmitSession increments the global publisher session count if below the cap.
func (g *GlobalBudget) AdmitSession() bool {
	if g.maxSessions <= 0 {
		g.activeSessions.Add(1)
		return true
	}
	for {
		cur := g.activeSessions.Load()
		if cur >= g.maxSessions {
			return false
		}
		if g.activeSessions.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// ReleaseSession decrements the global session count.
func (g *GlobalBudget) ReleaseSession() { g.activeSessions.Add(-1) }

// Stats returns current active counts for observability.
func (g *GlobalBudget) Stats() (httpStreams, wsStreams, sessions int64) {
	return g.activeHTTP.Load(), g.activeWS.Load(), g.activeSessions.Load()
}

// Saturated returns true if any limited resource class is at or above its cap.
func (g *GlobalBudget) Saturated() bool {
	if g.maxHTTPStreams > 0 && g.activeHTTP.Load() >= g.maxHTTPStreams {
		return true
	}
	if g.maxWSStreams > 0 && g.activeWS.Load() >= g.maxWSStreams {
		return true
	}
	if g.maxSessions > 0 && g.activeSessions.Load() >= g.maxSessions {
		return true
	}
	return false
}
