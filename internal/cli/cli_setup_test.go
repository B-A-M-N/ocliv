package cli

// Slice 1 acceptance: `setup --check` against injected echo endpoints
// reports the observed egress and a path verdict without touching DNS,
// routers, services, or credentials.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ocliv/internal/apperr"
)

func TestSetupCheckReportsEchoVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer srv.Close()
	out := captureStdout(t, func() {
		if code := cmdSetup([]string{"--check", "--echo-v4", srv.URL, "--echo-v6", ""}); code != apperr.ExitOK {
			t.Fatalf("exit=%d", code)
		}
	})
	for _, want := range []string{"203.0.113.9", "nat-ipv4-needs-forward", "UNKNOWN"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup --check missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "direct-ipv4") {
		t.Fatalf("setup --check overclaims direct reachability:\n%s", out)
	}
}

func TestSetupRejectsUnknownFlag(t *testing.T) {
	if code := cmdSetup([]string{"--bogus"}); code != apperr.ExitCLIValidation {
		t.Fatalf("exit=%d, want %d", code, apperr.ExitCLIValidation)
	}
}
