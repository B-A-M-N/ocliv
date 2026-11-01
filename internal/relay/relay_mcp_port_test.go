package relay

import (
	"path/filepath"
	"testing"

	"ocliv/internal/store"
)

// Minted route URLs must carry a non-443 public edge port: the lab Caddy
// listens on 8444, and a URL without the port points at a closed port
// while Host matching (which strips numeric ports) still admits traffic.
// Default 443 stays omitted. Failing-first for the --mcp-port slice.
func TestRouteURLMintingCarriesNonDefaultPort(t *testing.T) {
	newServer := func(t *testing.T, port int) *Server {
		t.Helper()
		db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		s, err := New(Options{
			DB: db, Namespace: "t.example.test",
			RelayHost:       "relay.example.test",
			MCPExternalHost: "relay.example.test",
			MCPExternalPort: port,
		})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	if got := newServer(t, 0).mcpBaseURL(); got != "https://relay.example.test" {
		t.Fatalf("default port minted %q, want bare https URL", got)
	}
	if got := newServer(t, 443).mcpBaseURL(); got != "https://relay.example.test" {
		t.Fatalf("explicit 443 minted %q, want bare https URL", got)
	}
	if got := newServer(t, 8444).mcpBaseURL(); got != "https://relay.example.test:8444" {
		t.Fatalf("8444 edge minted %q, want port in URL", got)
	}
}
