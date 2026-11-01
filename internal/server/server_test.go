package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpoints(t *testing.T) {
	h := &Health{Ready: func() bool { return true }}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()
	for path, want := range map[string]int{
		"/health/live": 200, "/health/ready": 200, "/metrics": 200,
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s = %d, want %d", path, resp.StatusCode, want)
		}
	}
	h.Ready = func() bool { return false }
	resp, err := http.Get(srv.URL + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unready = %d, want 503", resp.StatusCode)
	}
}
