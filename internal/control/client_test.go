package control

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"ocliv/internal/identity"
)

func TestClientNilKeyAndFailClosedNegotiation(t *testing.T) {
	c := NewClient("https://127.0.0.1:1", nil, "key-none")
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

	c2 := NewClient(srv.URL, kp, "key-"+string(kp.ID()))
	if _, _, err := c2.CallBody(http.MethodPost, "/v1/agent/key/rotate", []byte(`{"x":1}`)); err == nil {
		t.Fatalf("expected fail-closed error when capabilities & challenge both 404")
	}
	if mutationHits.Load() != 0 {
		t.Fatalf("expected 0 mutation hits, got %d", mutationHits.Load())
	}
}
