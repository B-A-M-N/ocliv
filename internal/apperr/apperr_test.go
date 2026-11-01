package apperr

import (
	"errors"
	"testing"
)

// ExitFor is the CLI's stable exit-status contract (P1-02): each fault
// class maps to a distinct, documented status.
func TestExitForMapping(t *testing.T) {
	cases := map[Code]int{
		CodeCLIValidation: ExitCLIValidation,
		CodeBadHost:       ExitCLIValidation,
		CodeLocalUnreach:  ExitLocalTarget,
		CodeEnrollAuth:    ExitAuth,
		CodeRevoked:       ExitAuth,
		CodeStaleGen:      ExitAuth,
		CodeTLSVerify:     ExitRelayTLS,
		CodeAgentOffline:  ExitRelayTLS,
		CodeProtocol:      ExitProtocol,
		CodeRateLimit:     ExitQuotaLease,
		CodeConflict:      ExitQuotaLease,
		Code("no-such"):   ExitInternal,
	}
	for code, want := range cases {
		if got := ExitFor(code); got != want {
			t.Fatalf("ExitFor(%q) = %d, want %d", code, got, want)
		}
	}
}

func TestErrorUnwrap(t *testing.T) {
	inner := errors.New("boom")
	e := E(CodeInternal, "outer", inner)
	if e.Error() == "" || !errors.Is(e, inner) {
		t.Fatal("error chain broken")
	}
}
