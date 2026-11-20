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
	"time"
)

func askCode(s *Server, host, remote, domain string) int {
	return servePeer(s, http.MethodGet, "/v1/internal/ask?domain="+domain, host, remote)
}

func TestAskRequiresDurableLeaseAuthority(t *testing.T) {
	s := newAuthorityServer(t)
	// Unallocated syntactically valid tunnel host must be DENIED (cannot burn ACME quota).
	if code := askCode(s, "127.0.0.1:8080", "127.0.0.1:9", "xyz.t.example.test"); code == http.StatusOK {
		t.Fatalf("ask approved unallocated tunnel host xyz.t.example.test")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.db.SQL().Exec(`INSERT OR IGNORE INTO tenants(id, status, created_at) VALUES('t1','active',?)`, now)
	_, _ = s.db.SQL().Exec(`INSERT OR IGNORE INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES('k1','t1',X'00','active',?)`, now)
	insert := func(id, label, status string, persistent int) {
		t.Helper()
		if _, err := s.db.SQL().Exec(
			`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, persistent, created_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			id, "t1", "k1", label+".t.example.test", label, 3000, "protected", 1, status, persistent, now); err != nil {
			t.Fatal(err)
		}
	}
	insert("l-active", "activeapp", "ACTIVE", 0)
	insert("l-precon", "persistoff", "RECONNECTING", 1)
	insert("l-erecon", "ephemoff", "RECONNECTING", 0)
	insert("l-exp", "expiredapp", "EXPIRED", 1)
	insert("l-rev", "revokedapp", "REVOKED", 1)
	insert("l-cls", "closedapp", "CLOSED", 1)

	if code := askCode(s, "127.0.0.1:8080", "127.0.0.1:9", "activeapp.t.example.test"); code != http.StatusOK {
		t.Fatalf("ask for ACTIVE lease: got %d want 200", code)
	}
	if code := askCode(s, "127.0.0.1:8080", "127.0.0.1:9", "persistoff.t.example.test"); code != http.StatusOK {
		t.Fatalf("ask for persistent RECONNECTING lease: got %d want 200", code)
	}
	for _, denied := range []string{
		"ephemoff.t.example.test",
		"expiredapp.t.example.test",
		"revokedapp.t.example.test",
		"closedapp.t.example.test",
	} {
		if code := askCode(s, "127.0.0.1:8080", "127.0.0.1:9", denied); code == http.StatusOK {
			t.Errorf("ask approved ineligible lease host %q", denied)
		}
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
