package relay

import (
	"net/http"
	"strings"

	"ocliv/internal/lease"
)

// authorizeHost polices the two dangerous cross-authority cases: agent
// control served on any authority but the relay hostname, and visitor
// traffic served on the control authority itself. Agent control requires
// the configured relay authority EXACTLY — there is no loopback-peer or
// loopback-Host exception. Caddy forwards over loopback too, so peer
// identity alone cannot authorize the control plane; a request bearing a
// loopback Host is either direct same-machine traffic that must still name
// the relay authority, or edge-forwarded traffic that must not reach agent
// handlers. Caddy preserves the public Host over its loopback forward, so
// edge traffic is governed by the public authorities; SNI/Host consistency
// is enforced at the Caddy edge, which has no catch-all site. Anything
// else falls through to the legacy router, which fails closed (404
// unknown, 400 malformed) without forwarding or touching localhost.
func (s *Server) authorizeHost(w http.ResponseWriter, r *http.Request) bool {
	host := canonicalHost(r.Host)
	if isAgentPath(r.URL.Path) {
		// Strict relay authority (MCP amendment P0, M11): no
		// loopback-peer bypass. Tests present the relay authority
		// while dialing loopback, exactly like Caddy-forwarded
		// production traffic.
		if host == s.relayHost {
			return true
		}
		http.Error(w, "misdirected: agent control requires the relay hostname", http.StatusMisdirectedRequest)
		return false
	}
	if s.mcpHost != "" && host == s.mcpHost {
		// Single-host ingress (P0-A): the configured external MCP
		// hostname may share the control authority — one FQDN serves
		// agent control and /r/<route-id>/mcp. Route-shaped MCP paths
		// pass through to handlePublic, which admits them against the
		// route binding, lease status, and generation, or fails closed
		// (404/503) without reaching any other handler class. Every
		// other path on the control authority keeps the 421 below, and
		// agent paths keep the strict branch above.
		if _, ok := parseMCPRoutePath(r.URL.EscapedPath()); ok {
			return true
		}
	}
	if host == s.relayHost {
		http.Error(w, "misdirected: visitor traffic requires a tunnel hostname", http.StatusMisdirectedRequest)
		return false
	}
	return true
}

// canonicalHost lowercases, strips any port, and trims a trailing FQDN dot,
// matching the normalization SplitHost applies before namespace comparison.
func canonicalHost(hostport string) string {
	host := hostport
	if i := strings.LastIndex(host, ":"); i >= 0 {
		if rest := host[i+1:]; rest != "" && isNumericPort(rest) {
			host = host[:i]
		}
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func isNumericPort(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isAgentPath reports the agent control-plane paths bound to the relay
// authority (enrollment, challenge, connect, signed lease management).
func isAgentPath(p string) bool {
	switch p {
	case "/v1/agent/enroll", "/v1/agent/challenge", "/v1/agent/connect":
		return true
	}
	return strings.HasPrefix(p, "/v1/agent/lease/")
}

// splitTunnelHost uses the lease package's exact-Host parser so the
// authority check and the routing decision share one definition.
func splitTunnelHost(hostport, ns string) (string, bool) {
	return lease.SplitHost(hostport, ns)
}

// rejectConnect answers CONNECT with 400: no open proxy or tunnel setup is
// ever performed on behalf of a visitor (D11).
func rejectConnect(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "connect not supported", http.StatusBadRequest)
}
