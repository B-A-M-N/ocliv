package relay

// On-demand TLS ask contract (Slice 4a): Caddy asks the relay over
// loopback whether it may issue a certificate for a domain. Only
// tunnel hostnames under the configured namespace are ever approved,
// and only when the asker is the local edge itself (loopback peer
// presenting a loopback Host — Caddy dials the ask URL directly, it
// never forwards a visitor Host here). Anything else falls through to
// normal dispatch and never receives an approval.

import (
	"net/http"
	"testing"
)

func askCode(s *Server, host, remote, domain string) int {
	return servePeer(s, http.MethodGet, "/v1/internal/ask?domain="+domain, host, remote)
}

func TestAskApprovesTunnelHostForLocalEdge(t *testing.T) {
	s := newAuthorityServer(t)
	if code := askCode(s, "127.0.0.1:8080", "127.0.0.1:9", "xyz.t.example.test"); code != http.StatusOK {
		t.Fatalf("ask for tunnel host from local edge: got %d want 200", code)
	}
}

func TestAskDeniesNonTunnelDomains(t *testing.T) {
	s := newAuthorityServer(t)
	for _, d := range []string{
		"relay.example.test", "evil.test", "xyz.t.other.test",
		"t.example.test", "", "x..t.example.test",
	} {
		if code := askCode(s, "127.0.0.1:8080", "127.0.0.1:9", d); code == http.StatusOK {
			t.Errorf("ask approved %q from local edge", d)
		}
	}
}

func TestAskNeverApprovesOffLoopback(t *testing.T) {
	s := newAuthorityServer(t)
	// Non-loopback peer, even with a loopback Host: not the local edge.
	if code := askCode(s, "127.0.0.1:8080", "203.0.113.9:9", "xyz.t.example.test"); code == http.StatusOK {
		t.Fatal("ask approved for non-loopback peer")
	}
	// Loopback peer (Caddy-forwarded shape) but a public Host: a visitor
	// Host must never reach the ask decision.
	if code := askCode(s, "evil.test", "127.0.0.1:9", "xyz.t.example.test"); code == http.StatusOK {
		t.Fatal("ask approved under a visitor Host")
	}
	if code := askCode(s, "relay.example.test", "127.0.0.1:9", "xyz.t.example.test"); code == http.StatusOK {
		t.Fatal("ask approved under the control authority")
	}
}
