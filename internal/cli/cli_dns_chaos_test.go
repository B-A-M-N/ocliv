package cli

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ocliv/internal/apperr"
)

// Chaos D1: DNS hijack (or stale record) pointing the relay hostname at
// a cleartext LAN impostor must fail closed BEFORE any code is sent.
// performEnroll must refuse non-loopback http with a validation exit —
// never an auth/network exit that would imply a dial happened.
func TestEnrollRefusesCleartextLANRelay(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, raw := range []string{
		"http://10.9.66.20:8080",
		"http://relay.ocliv.test:8080",
	} {
		if _, code := performEnroll(raw, "DUMMYCODE", ""); code != apperr.ExitCLIValidation {
			t.Fatalf("cleartext LAN relay %q not refused pre-network (exit %d)", raw, code)
		}
	}
}

// Chaos D2: an unresolvable relay hostname must fail bounded with an
// auth/unreachable exit and leave zero enrollment state behind.
func TestEnrollUnresolvableHostFailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, code := performEnroll("https://unresolvable.invalid.", "DUMMYCODE", ""); code != apperr.ExitAuth {
		t.Fatalf("unresolvable relay exit = %d, want %d", code, apperr.ExitAuth)
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".config", "ocliv", "*"))
	if len(matches) != 0 {
		t.Fatalf("failed enrollment left state behind: %v", matches)
	}
}

// Chaos D3: a TLS impostor (wrong identity for the relay URL) must
// never receive the enrollment POST. The handshake must die first.
func TestEnrollSendsNothingToTLSImpostor(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var posts int
	impostor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agent/enroll" {
			posts++
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"key_id":"x","tenant_id":"y"}`))
	}))
	defer impostor.Close()
	if _, code := performEnroll(impostor.URL, "DUMMYCODE", ""); code != apperr.ExitAuth {
		t.Fatalf("TLS impostor exit = %d, want %d", code, apperr.ExitAuth)
	}
	if posts != 0 {
		t.Fatalf("enrollment code POSTed %d times to an unverified TLS identity", posts)
	}
}
