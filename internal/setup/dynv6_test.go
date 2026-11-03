package setup

// dynv6 Update API contract (Slice 2): authenticated dynamic address
// update for a *.dynv6.net zone. The HTTP token travels only in the
// request query (as the API requires) and in owner-only storage; it
// never appears in errors, logs, or CLI output.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDynv6UpdateSendsAuthParams(t *testing.T) {
	var gotHost, gotToken, gotV4, gotV6 string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotHost, gotToken, gotV4, gotV6 = q.Get("hostname"), q.Get("token"), q.Get("ipv4"), q.Get("ipv6")
		_, _ = w.Write([]byte("addresses updated"))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := UpdateDynv6(ctx, srv.URL, "bamnlabs.dynv6.net", "TESTTOKEN", "203.0.113.9", "2001:db8::1"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if gotHost != "bamnlabs.dynv6.net" || gotToken != "TESTTOKEN" || gotV4 != "203.0.113.9" || gotV6 != "2001:db8::1" {
		t.Fatalf("params host=%q token=%q v4=%q v6=%q", gotHost, gotToken, gotV4, gotV6)
	}
}

func TestDynv6UpdateRejectsNonDynv6Zone(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := UpdateDynv6(ctx, srv.URL, "example.com", "TESTTOKEN", "203.0.113.9", ""); err == nil {
		t.Fatal("non-dynv6 zone accepted")
	}
	if hit {
		t.Fatal("rejected zone still hit the network")
	}
}

func TestDynv6UpdateRequiresToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := UpdateDynv6(ctx, "http://127.0.0.1:1", "bamnlabs.dynv6.net", "", "203.0.113.9", ""); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestDynv6TransportErrorHidesToken(t *testing.T) {
	// A refused connection surfaces as *url.Error whose message
	// embeds the request URL — including the token query. The
	// returned error must never carry it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := UpdateDynv6(ctx, "http://127.0.0.1:1", "bamnlabs.dynv6.net", "SECRETTOKEN", "203.0.113.9", "")
	if err == nil {
		t.Fatal("refused connection treated as success")
	}
	if strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("token leaked into transport error: %v", err)
	}
	if !strings.Contains(err.Error(), "bamnlabs.dynv6.net") {
		t.Fatalf("sanitized error lost the zone context: %v", err)
	}
}

func TestDynv6UpdateErrorHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("badauth"))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := UpdateDynv6(ctx, srv.URL, "bamnlabs.dynv6.net", "SECRETTOKEN", "203.0.113.9", "")
	if err == nil {
		t.Fatal("401 treated as success")
	}
	if strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("token leaked into error: %v", err)
	}
}

// Task 1: URL encoding changes the token's representation
// (q.Encode percent-encodes + / = & and space), so literal-only
// redaction leaves the encoded credential visible in *url.Error text
// and in echoed provider bodies. Neither form may leak.
func TestDynv6EncodedTokenNeverLeaks(t *testing.T) {
	token := "tok+en/with=special&chars here"
	encoded := []string{token, "tok%2Ben%2Fwith%3Dspecial%26chars+here", "tok%2Ben%2Fwith%3Dspecial%26chars%20here"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := UpdateDynv6(ctx, "http://127.0.0.1:1", "bamnlabs.dynv6.net", token, "203.0.113.9", "")
	if err == nil {
		t.Fatal("refused connection treated as success")
	}
	for _, form := range encoded {
		if strings.Contains(err.Error(), form) {
			t.Fatalf("token form leaked into transport error: %q in %v", form, err)
		}
	}
	if !strings.Contains(err.Error(), "bamnlabs.dynv6.net") {
		t.Fatalf("sanitized error lost the zone context: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("sanitized error lost the failure category: %v", err)
	}
	// Provider body echoing the encoded URL must be sanitized too.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad auth for token=tok%2Ben%2Fwith%3Dspecial%26chars+here"))
	}))
	defer srv.Close()
	err = UpdateDynv6(ctx, srv.URL, "bamnlabs.dynv6.net", token, "203.0.113.9", "")
	if err == nil {
		t.Fatal("401 treated as success")
	}
	for _, form := range encoded {
		if strings.Contains(err.Error(), form) {
			t.Fatalf("token form leaked into provider error: %q in %v", form, err)
		}
	}
}
