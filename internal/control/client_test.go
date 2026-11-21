package control

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"ocliv/internal/identity"
)

// TestHTTPClientRefusesRedirects verifies that HTTPClient never follows HTTP
// redirects for any status code, so that X-Ocliv-* auth headers and request
// bodies are never forwarded to a redirect target.
func TestHTTPClientRefusesRedirects(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		code := code
		t.Run(fmt.Sprintf("%d", code), func(t *testing.T) {
			var targetHits atomic.Int32
			var targetReceivedBody atomic.Bool
			var targetReceivedAuthHeader atomic.Bool

			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				b := make([]byte, 64)
				n, _ := r.Body.Read(b)
				if n > 0 {
					targetReceivedBody.Store(true)
				}
				if r.Header.Get("X-Ocliv-Key") != "" || r.Header.Get("X-Ocliv-Sig") != "" {
					targetReceivedAuthHeader.Store(true)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer target.Close()

			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+r.URL.Path, code)
			}))
			defer origin.Close()

			c, err := HTTPClient(0)
			if err != nil {
				t.Fatalf("HTTPClient: %v", err)
			}

			body := []byte(`{"secret":"enrollment-code","public_key":"abc123"}`)
			req, _ := http.NewRequest(http.MethodPost, origin.URL+"/v1/agent/enroll", bytes.NewReader(body))
			req.Header.Set("X-Ocliv-Key", "key-test")
			req.Header.Set("X-Ocliv-Sig", "sig-value")
			resp, err := c.Do(req)
			if err != nil {
				// ErrUseLastResponse surfaces as an error on some Go versions.
				// What matters: target got zero hits.
			} else {
				resp.Body.Close()
				// The redirect response itself should be returned, not the target's.
				if resp.StatusCode != code {
					t.Errorf("status %d: got response status %d, want redirect code %d (not following)", code, resp.StatusCode, code)
				}
			}

			if targetHits.Load() != 0 {
				t.Errorf("status %d: redirect target received %d request(s); expected 0", code, targetHits.Load())
			}
			if targetReceivedBody.Load() {
				t.Errorf("status %d: redirect target received request body (credential leak)", code)
			}
			if targetReceivedAuthHeader.Load() {
				t.Errorf("status %d: redirect target received X-Ocliv-* auth headers (credential leak)", code)
			}
		})
	}
}

// TestValidateRelayURL exercises the URL validation rules.
func TestValidateRelayURL(t *testing.T) {
	cases := []struct {
		raw     string
		wantErr bool
	}{
		// Valid
		{"https://relay.example.net", false},
		{"https://relay.example.net:8443", false},
		{"http://127.0.0.1:8080", false},
		{"http://localhost:8080", false},
		{"http://[::1]:8080", false},
		// Scheme errors
		{"", true},
		{"ftp://relay.example.net", true},
		{"ws://relay.example.net", true},
		{"http://relay.example.net", true}, // non-loopback http
		// Userinfo
		{"https://user:pass@relay.example.net", true},
		{"https://user@relay.example.net", true},
		// Fragment
		{"https://relay.example.net#section", true},
		// Query
		{"https://relay.example.net?foo=bar", true},
		// Empty host
		{"https://", true},
		// Non-root path
		{"https://relay.example.net/v1", true},
		{"https://relay.example.net/api/path", true},
		// Trailing slash is valid (treated as root)
		{"https://relay.example.net/", false},
	}
	for _, tc := range cases {
		err := ValidateRelayURL(tc.raw)
		if tc.wantErr && err == nil {
			t.Errorf("ValidateRelayURL(%q): expected error, got nil", tc.raw)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ValidateRelayURL(%q): unexpected error: %v", tc.raw, err)
		}
	}
}

func TestClientNilKeyAndFailClosedNegotiation(t *testing.T) {
	c, err := NewClient("https://127.0.0.1:1", nil, "key-none")
	if err != nil {
		t.Fatalf("unexpected NewClient error: %v", err)
	}
	if _, _, err := c.Call(http.MethodGet, "/v1/agent/leases"); err == nil {
		t.Fatalf("expected error on nil key")
	}

	kp, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var mutationHits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agent/key/rotate" {
			mutationHits.Add(1)
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCLIV_CACERT", caPath)

	c2, err := NewClient(srv.URL, kp, "key-"+string(kp.ID()))
	if err != nil {
		t.Fatalf("unexpected NewClient error: %v", err)
	}
	if _, _, err := c2.CallBody(http.MethodPost, "/v1/agent/key/rotate", []byte(`{"x":1}`)); err == nil {
		t.Fatalf("expected fail-closed error when capabilities & challenge both 404")
	}
	if mutationHits.Load() != 0 {
		t.Fatalf("expected 0 mutation hits, got %d", mutationHits.Load())
	}
}

// TestNewClientRejectsPath verifies that NewClient fails when the URL contains
// a non-root path component, preventing misconfigured clients from silently
// routing to wrong endpoints.
func TestNewClientRejectsPath(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://relay.example.net", false},
		{"https://relay.example.net/", false},
		{"https://relay.example.net/v1", true},
		{"https://relay.example.net/api/path", true},
		{"http://not-loopback.example.net", true},
		{"", true},
	}
	for _, tc := range cases {
		_, err := NewClient(tc.url, nil, "key-test")
		if tc.wantErr && err == nil {
			t.Errorf("NewClient(%q): expected error, got nil", tc.url)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("NewClient(%q): unexpected error: %v", tc.url, err)
		}
	}
}
