package cli

import (
	"net"
	"strings"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/identity"
)

func TestManagementCallReturnsTransportError(t *testing.T) {
	t.Setenv("OCLIV_CACERT", "")
	key, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	status, body, err := mgmtCall(endpoint, key, string(key.ID()), "GET", "/status")
	if err == nil || status != 0 || body != nil {
		t.Fatalf("status=%d body=%q err=%v, want explicit transport error", status, body, err)
	}
	if !strings.Contains(err.Error(), "management transport failure") {
		t.Fatalf("transport error category missing: %v", err)
	}
}
