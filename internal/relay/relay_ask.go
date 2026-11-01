package relay

import (
	"net/http"
	"strings"
)

// askPath is the on-demand TLS authorization endpoint Caddy queries
// before issuing a certificate for a tunnel hostname. Caddy dials it
// directly (never forwards a visitor Host here), so approval requires
// a loopback peer presenting a loopback Host: that combination is the
// local edge itself. The approved set is exactly the tunnel namespace
// (splitTunnelHost), shared with the routing decision so ask and route
// can never disagree about what counts as a tunnel hostname.
const askPath = "/v1/internal/ask"

// askAllowed reports whether r is the local edge asking about a tunnel
// hostname under the configured namespace.
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
	_, ok := splitTunnelHost(domain, s.namespace)
	return ok
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
