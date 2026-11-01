package relay

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// TestPublicSchemeTrustsOnlyEdge: X-Forwarded-Proto is honored only from
// the trusted edge. Direct TLS is authoritative; loopback (local Caddy)
// may assert it; remote plaintext must never upgrade itself to https,
// or CSRF origin checks and forwarded proto would be spoofable (D08).
func TestPublicSchemeTrustsOnlyEdge(t *testing.T) {
	mk := func(tlsOn bool, remote, xfp string) *http.Request {
		r, _ := http.NewRequest("GET", "http://t.example.test/", nil)
		r.RemoteAddr = remote
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		if xfp != "" {
			r.Header.Set("X-Forwarded-Proto", xfp)
		}
		return r
	}
	cases := []struct {
		name       string
		req        *http.Request
		want       string
		wantOrigin string
	}{
		{"direct TLS", mk(true, "203.0.113.7:443", ""), "https", "https://t.example.test"},
		{"loopback edge asserts https", mk(false, "127.0.0.1:8080", "https"), "https", "https://t.example.test"},
		{"loopback plain stays http", mk(false, "127.0.0.1:8080", ""), "http", "http://t.example.test"},
		{"remote spoof ignored", mk(false, "203.0.113.7:1234", "https"), "http", "http://t.example.test"},
		{"remote plain stays http", mk(false, "203.0.113.7:1234", ""), "http", "http://t.example.test"},
	}
	for _, c := range cases {
		if got := publicScheme(c.req); got != c.want {
			t.Errorf("%s: scheme=%q want %q", c.name, got, c.want)
		}
		if got := tunnelOrigin(c.req); got != c.wantOrigin {
			t.Errorf("%s: origin=%q want %q", c.name, got, c.wantOrigin)
		}
	}
}
