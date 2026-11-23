package relay

import (
	"net/http"
	"strings"

	"github.com/B-A-M-N/ocliv/internal/lease"
)

// askPath is the on-demand TLS authorization endpoint Caddy queries
// before issuing a certificate for a tunnel hostname. Caddy dials it
// directly (never forwards a visitor Host here), so approval requires
// a loopback peer presenting a loopback Host AND an actual durable
// Ocliv lease reservation (ACTIVE or persistent RECONNECTING).
const askPath = "/v1/internal/ask"

// askAllowed reports whether r is the local edge asking about an actually
// allocated, eligible tunnel hostname under the configured namespace.
// Unknown, expired, revoked, closed, or ephemeral-reconnecting hostnames
// are denied so arbitrary wildcard probing cannot burn ACME issuance quota.
func (s *Server) askAllowed(r *http.Request) bool {
	if r.URL.Path != askPath {
		return false
	}
	if !isLoopback(r.RemoteAddr) {
		return false
	}
	if !isLoopbackIP(canonicalHost(r.Host)) {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if domain == "" {
		return false
	}
	if _, ok := splitTunnelHost(domain, s.namespace); !ok {
		return false
	}
	if s.db == nil {
		return false
	}
	var status string
	var persistentInt int
	err := s.db.SQL().QueryRow(
		`SELECT status, COALESCE(persistent, 0) FROM leases WHERE hostname=?`, domain,
	).Scan(&status, &persistentInt)
	if err != nil {
		return false
	}
	switch status {
	case string(lease.StateActive):
		// Active lease is eligible for issuance/renewal.
	case string(lease.StateReconnecting):
		// Only persistent hosted reservations retain cert renewal eligibility while offline.
		if persistentInt == 0 {
			return false
		}
	default:
		// EXPIRED, REVOKED, CLOSED, etc. are strictly denied.
		return false
	}
	if s.throttle != nil && !s.throttle.Allow("ask:"+domain) {
		return false
	}
	return true
}

// handleAsk answers Caddy's issuance probe. Denials are 404,
// indistinguishable from an unknown path, so probing reveals nothing
// about the namespace shape.
func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	if !s.askAllowed(r) {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
