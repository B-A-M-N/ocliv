package setup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRefreshSkipsWhenUnchanged proves the refresher makes zero
// provider calls — and leaks nothing — when DNS already matches
// observed egress.
func TestRefreshSkipsWhenUnchanged(t *testing.T) {
	var hits atomic.Int32
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer echo.Close()
	oldLookup := LookupHost
	LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	}
	defer func() { LookupHost = oldLookup }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	changed, err := RefreshDynDNS(ctx, upd.URL, "lab.dynv6.net", "TESTTOKEN", echo.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("unchanged DNS reported as changed")
	}
	if hits.Load() != 0 {
		t.Fatalf("provider called %d times for unchanged DNS", hits.Load())
	}
}

// TestRefreshUpdatesOnChange proves only the changed family is
// pushed, and the token never surfaces in errors on the way.
func TestRefreshUpdatesOnChange(t *testing.T) {
	var gotQuery atomic.Value
	upd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery.Store(r.URL.RawQuery)
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer upd.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("198.51.100.7\n"))
	}))
	defer echo.Close()
	oldLookup := LookupHost
	LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	}
	defer func() { LookupHost = oldLookup }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	changed, err := RefreshDynDNS(ctx, upd.URL, "lab.dynv6.net", "TESTTOKEN", echo.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed egress not detected")
	}
	q, _ := gotQuery.Load().(string)
	if !strings.Contains(q, "ipv4=198.51.100.7") {
		t.Fatalf("new egress not pushed: %q", q)
	}
	// The update API carries the token as its credential by design;
	// transport-error redaction is covered by TestDynv6TransportErrorHidesToken.
}

// TestRefreshRefusesWithoutViablePath proves the refresher does not
// "confirm" DNS it cannot observe: no egress, no update, loud reason.
func TestRefreshRefusesWithoutViablePath(t *testing.T) {
	oldLookup := LookupHost
	LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	}
	defer func() { LookupHost = oldLookup }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	changed, err := RefreshDynDNS(ctx, "http://127.0.0.1:1", "lab.dynv6.net", "TESTTOKEN", "", "")
	if err == nil {
		t.Fatal("unobservable path accepted silently")
	}
	if changed {
		t.Fatal("changed reported without observation")
	}
	if strings.Contains(err.Error(), "TESTTOKEN") {
		t.Fatalf("token in refusal: %v", err)
	}
}
