package setup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Chaos E1: overlapping timer runs of RefreshDynDNS must converge, not
// corrupt. The update server blocks until all K concurrent refreshers
// have arrived (forcing true overlap), then releases them at once.
// dynv6 updates are idempotent record-sets, so every request must push
// the same observed egress values and all callers must succeed.
func TestConcurrentRefreshOverlapConverges(t *testing.T) {
	const K = 8
	var arrived atomic.Int32
	release := make(chan struct{})
	var mu sync.Mutex
	var queries []string
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := arrived.Add(1)
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()
		if n == K {
			close(release)
		}
		select {
		case <-release:
		case <-time.After(10 * time.Second):
			http.Error(w, "test barrier stuck", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("198.51.100.7\n"))
	}))
	defer echo.Close()
	oldLookup := LookupHost
	LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil // stale: forces update path
	}
	defer func() { LookupHost = oldLookup }()

	var wg sync.WaitGroup
	errs := make([]error, K)
	changed := make([]bool, K)
	for i := 0; i < K; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			changed[i], errs[i] = RefreshDynDNS(ctx, upd.URL, "lab.dynv6.net", "TESTTOKEN", echo.URL, "")
		}(i)
	}
	wg.Wait()
	for i := 0; i < K; i++ {
		if errs[i] != nil {
			t.Fatalf("refresher %d failed under overlap: %v", i, errs[i])
		}
		if !changed[i] {
			t.Fatalf("refresher %d missed the change under overlap", i)
		}
	}
	if len(queries) != K {
		t.Fatalf("expected %d provider updates, got %d", K, len(queries))
	}
	for _, q := range queries {
		if !strings.Contains(q, "ipv4=198.51.100.7") {
			t.Fatalf("divergent update under overlap: %q", q)
		}
		if strings.Contains(q, "TESTTOKEN") == false {
			t.Fatalf("token missing from provider update: %q", q)
		}
	}
}
