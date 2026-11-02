package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"ocliv/internal/identity"
	"ocliv/internal/limits"
	"ocliv/internal/store"
)

// newLimitServer builds a relay with a permissive pre-auth limiter so the
// nonce table can be flooded through the real challenge endpoint (G08).
// Only the orthogonal pre-auth limiter is relaxed; the nonce cap is live.
func newLimitServer(t *testing.T) (*Server, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	s.preAuth = limits.NewThrottle(1<<30, time.Minute)
	code, err := IssueEnrollmentCode(db, "tenant-test", time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"code": code, "public_key": base64.StdEncoding.EncodeToString(k.Public()),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", bytes.NewReader(body))
	r.Host = "relay.example.test"
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll status %d", w.Code)
	}
	return s, "key-" + string(k.ID())
}

func postChallenge(s *Server, keyID string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"key_id": keyID})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/agent/challenge", bytes.NewReader(body))
	r.Host = "relay.example.test"
	r.RemoteAddr = "127.0.0.1:9999"
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestNonceTableBounded: a challenge flood through the production endpoint
// fails closed at the nonce cap instead of growing the map (G08).
// The edge strips inbound X-Forwarded-* and asserts the real client IP,
// so a loopback peer means the request came through the edge: the
// rightmost forwarded entry is the client. A non-loopback peer means the
// edge was bypassed: forwarded headers are ignored (P1-06).
func TestClientIPHonorsEdgeForwarding(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"edge client", "127.0.0.1:5000", "203.0.0.7", "203.0.0.7"},
		{"edge appends", "127.0.0.1:5000", "victim, 198.51.100.9", "198.51.100.9"},
		{"edge no header", "127.0.0.1:5000", "", "127.0.0.1"},
		{"edge ipv6", "[::1]:5000", "2001:db8::7", "2001:db8::7"},
		{"direct spoof ignored", "203.0.0.9:5000", "10.9.9.9", "203.0.0.9"},
		{"direct no header", "203.0.0.9:5000", "", "203.0.0.9"},
		{"malformed falls back", "127.0.0.1:5000", "not-an-ip", "127.0.0.1"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := clientIP(r); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// Two external clients behind the simulated edge get independent
// pre-auth quotas even though they share the loopback peer (P1-06).
func TestPreAuthQuotasIndependentBehindEdge(t *testing.T) {
	s, _ := newLimitServer(t)
	s.preAuth = limits.NewThrottle(2, time.Minute)
	visitor := func(xff string) *http.Request {
		r := httptest.NewRequest("POST", "/_ocliv/challenge", nil)
		r.RemoteAddr = "127.0.0.1:5000"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	w := httptest.NewRecorder()
	// Exhaust client A (burst 2 + 1 denied).
	if !s.checkPreAuth(w, visitor("203.0.0.7"), "challenge") {
		t.Fatal("client A first request denied")
	}
	if !s.checkPreAuth(w, visitor("203.0.0.7"), "challenge") {
		t.Fatal("client A second request denied")
	}
	if s.checkPreAuth(w, visitor("203.0.0.7"), "challenge") {
		t.Fatal("client A over quota allowed")
	}
	// Client B is unaffected.
	if !s.checkPreAuth(w, visitor("198.51.100.9"), "challenge") {
		t.Fatal("client B denied by client A's usage")
	}
}

// An isolated edge enforcing the Caddy contract (overwrite
// X-Forwarded-For with the downstream peer, strip X-Forwarded-Host)
// fronts the relay: rotating visitor-spoofed XFF values must not mint
// new quota, and a smuggled X-Forwarded-Host must not affect routing
// (Task C). Live funnel result 2026-11-02: 130 rotating spoofs through
// the public funnel shared one admission bucket (120x401 then 10x429).
func TestIsolatedEdgeContractOverwritesForwardedIdentity(t *testing.T) {
	s, _ := newLimitServer(t)
	s.preAuth = limits.NewThrottle(1, time.Minute)
	backend := httptest.NewServer(s.Handler())
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	edge := &httputil.ReverseProxy{Director: func(r *http.Request) {
		r.URL.Scheme = target.Scheme
		r.URL.Host = target.Host
		peer, _, _ := net.SplitHostPort(r.RemoteAddr)
		r.Header.Set("X-Forwarded-For", peer) // overwrite, never append
		r.Header.Del("X-Forwarded-Host")      // strip smuggled host
		r.Header.Set("X-Forwarded-Proto", "https")
	}}
	front := httptest.NewServer(edge)
	defer front.Close()
	hit := func(xff, xfh string) int {
		body := bytes.NewReader([]byte(`{"key_id":"nope"}`))
		req, err := http.NewRequest(http.MethodPost, front.URL+"/v1/agent/challenge", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "relay.example.test"
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		if xfh != "" {
			req.Header.Set("X-Forwarded-Host", xfh)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := hit("10.9.9.9", "evil.example"); code == http.StatusTooManyRequests {
		t.Fatal("first edge request denied")
	}
	// Different spoofed identity, same edge peer: shares the bucket.
	if code := hit("10.9.9.10", ""); code != http.StatusTooManyRequests {
		t.Fatalf("rotated spoof escaped the edge bucket: %d", code)
	}
}

// A direct (non-edge) peer cannot mint quota with spoofed forwarding
// headers: all requests from that peer share one bucket (P1-06).
func TestPreAuthSpoofedHeaderIgnoredDirect(t *testing.T) {
	s, _ := newLimitServer(t)
	s.preAuth = limits.NewThrottle(1, time.Minute)
	direct := func(xff string) *http.Request {
		r := httptest.NewRequest("POST", "/_ocliv/challenge", nil)
		r.RemoteAddr = "203.0.0.9:5000"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	w := httptest.NewRecorder()
	if !s.checkPreAuth(w, direct("10.9.9.9"), "challenge") {
		t.Fatal("direct first request denied")
	}
	// Different spoofed identity, same peer: must share the bucket.
	if s.checkPreAuth(w, direct("10.9.9.10"), "challenge") {
		t.Fatal("spoofed XFF escaped the peer bucket")
	}
}

func TestNonceTableBounded(t *testing.T) {
	s, keyID := newLimitServer(t)
	var last int
	for i := 0; i < limits.MaxNonceEntries+50; i++ {
		w := postChallenge(s, keyID)
		last = w.Code
		if w.Code == http.StatusTooManyRequests {
			break
		}
		if w.Code != http.StatusOK {
			t.Fatalf("challenge %d: status %d", i, w.Code)
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("nonce flood never failed closed (last=%d)", last)
	}
	if n := s.nonces.size(); n > limits.MaxNonceEntries {
		t.Fatalf("nonce table exceeded cap: %d", n)
	}
}

// TestNonceSweepReclaims: expired entries are swept before the cap check,
// so a table of dead nonces still admits a fresh challenge (no pinning).
func TestNonceSweepReclaims(t *testing.T) {
	s, keyID := newLimitServer(t)
	for i := 0; i < limits.MaxNonceEntries-1; i++ {
		if w := postChallenge(s, keyID); w.Code != http.StatusOK {
			t.Fatalf("challenge %d: status %d", i, w.Code)
		}
	}
	if !s.nonces.reserve("expired-test-nonce", time.Now().Add(-time.Hour)) {
		t.Fatal("could not plant expired nonce")
	}
	if w := postChallenge(s, keyID); w.Code != http.StatusOK {
		t.Fatalf("live challenge denied despite expired entry: %d", w.Code)
	}
}

// TestPreAuthFloodFailsClosed: hammering a pre-auth endpoint from one IP
// trips the per-IP limiter with 429s through the production handler (G07).
func TestPreAuthFloodFailsClosed(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Options{DB: db, Namespace: "t.example.test", RelayHost: "relay.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	seen429 := false
	for i := 0; i < limits.PreAuthBurst+50; i++ {
		w := postChallenge(s, "key-nonexistent")
		if w.Code == http.StatusTooManyRequests {
			seen429 = true
			break
		}
		// Unknown key is rejected as unauthorized until the limiter trips.
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("challenge %d: status %d, want 401-or-429", i, w.Code)
		}
	}
	if !seen429 {
		t.Fatal("pre-auth flood never hit 429")
	}
}
