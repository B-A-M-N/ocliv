package relay

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"ocliv/internal/lease"
)

// Chaos C3: concurrent duplicate route creations must converge on one
// stable route. The INSERT...SELECT/ON CONFLICT loop claims the loser
// re-reads the winner; without this test that claim is unproven and a
// duplicate-row or divergent-ID outcome would split the public
// endpoint identity.
func TestConcurrentRouteCreateConverges(t *testing.T) {
	s, db := newMCPServer(t)
	insertMCPLeaseRow(t, db, "lse-race", "race.t.example.test", AccessModeMCPUpstreamOAuth, lease.StateActive, 1, nil)
	priv := enrollTestKey(t, db.SQL(), "key-test", "tenant-test")
	liveFabricatedSession(t, s, "lse-race", 1)

	const K = 16
	type result struct {
		code  int
		route string
	}
	out := make([]result, K)
	var wg sync.WaitGroup
	for i := 0; i < K; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, body := postMCPRoute(t, s, priv, "key-test", "lse-race", "upstream-oauth")
			var rr struct {
				RouteID string `json:"route_id"`
			}
			_ = json.Unmarshal([]byte(body), &rr)
			out[i] = result{code, rr.RouteID}
		}(i)
	}
	wg.Wait()
	for i := 0; i < K; i++ {
		if out[i].code != http.StatusOK {
			t.Fatalf("creator %d: status=%d, want 200", i, out[i].code)
		}
		if out[i].route == "" {
			t.Fatalf("creator %d: empty route_id", i)
		}
		if out[i].route != out[0].route {
			t.Fatalf("divergent route ids: %q vs %q", out[i].route, out[0].route)
		}
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_publications WHERE lease_id=?`, "lse-race").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("concurrent create left %d rows, want exactly 1", n)
	}
}
