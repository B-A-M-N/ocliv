package proxy

// Isolated fuzz targets for the request-framing layer (H10). These run
// the production syntax checkers against arbitrary inputs and assert
// panic-freedom plus determinism. They add no production code and change
// no behavior; `go test` runs only the seed corpus.

import (
	"net/http"
	"testing"
)

// buildFuzzRequest assembles a request from fuzzer-controlled framing
// fields the same way the relay does before forwarding.
func buildFuzzRequest(method, uri, te, cl1, cl2, upgrade, connection string) *http.Request {
	r, err := http.NewRequest(method, "http://t.example.test/", nil)
	if err != nil || r == nil {
		r = &http.Request{Method: method, Header: make(http.Header)}
	}
	// Server-side shape: RequestURI carries the raw target.
	r.RequestURI = uri
	if te != "" {
		r.Header["Transfer-Encoding"] = []string{te}
	}
	if cl1 != "" {
		r.Header["Content-Length"] = []string{cl1}
		if cl2 != "" {
			r.Header["Content-Length"] = []string{cl1, cl2}
		}
	}
	if upgrade != "" {
		r.Header.Set("Upgrade", upgrade)
	}
	if connection != "" {
		r.Header.Set("Connection", connection)
	}
	return r
}

func FuzzCheckRequestSyntax(f *testing.F) {
	seeds := [][7]string{
		{"GET", "/", "", "", "", "", ""},
		{"POST", "/echo", "chunked", "", "", "", ""},
		{"GET", "/", "chunked", "5", "", "", ""},
		{"POST", "/", "", "5", "6", "", ""},
		{"CONNECT", "/", "", "", "", "", ""},
		{"TRACE", "/", "", "", "", "", ""},
		{"GET", "http://evil.example/", "", "", "", "", ""},
		{"GET", "/", "gzip", "", "", "", ""},
		{"GET", "/", "", "", "", "websocket", "Upgrade"},
		{"GET", "/", "", "", "", "h2c", "Upgrade"},
		{"", "", "", "", "", "", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2], s[3], s[4], s[5], s[6])
	}
	f.Fuzz(func(t *testing.T, method, uri, te, cl1, cl2, upgrade, connection string) {
		r := buildFuzzRequest(method, uri, te, cl1, cl2, upgrade, connection)
		first := CheckRequestSyntax(r)
		second := CheckRequestSyntax(r)
		if (first == nil) != (second == nil) {
			t.Fatalf("nondeterministic verdict for %q %q: %v vs %v", method, uri, first, second)
		}
	})
}

func FuzzCheckUpgradeSyntax(f *testing.F) {
	seeds := [][2]string{
		{"", ""},
		{"websocket", "Upgrade"},
		{"WebSocket", "keep-alive, Upgrade"},
		{"h2c", "Upgrade"},
		{"websocket", "keep-alive"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, upgrade, connection string) {
		r, _ := http.NewRequest("GET", "http://t.example.test/", nil)
		if upgrade != "" {
			r.Header.Set("Upgrade", upgrade)
		}
		if connection != "" {
			r.Header.Set("Connection", connection)
		}
		first := CheckUpgradeSyntax(r)
		second := CheckUpgradeSyntax(r)
		if (first == nil) != (second == nil) {
			t.Fatalf("nondeterministic verdict for %q: %v vs %v", upgrade, first, second)
		}
	})
}
