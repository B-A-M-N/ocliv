package cli

// P1: a terminal OWNERSHIP denial must print the right corrective action.
//
// The live release-candidate run exposed this: a second agent key in the
// same tenant publishing a held name TERMINATED correctly (no endless
// reconnect loop), but the CLI printed the generic credential hint —
// "tunnel credential rejected: run `ocliv login ...` to re-enroll". That
// advice is wrong: the credential is VALID; the NAME is taken. Following
// it would send the operator into a pointless re-enrollment loop.
//
// The mapping is keyed on the TYPED sentinel (agent.ErrLeaseOwnership),
// never on message wording, so a wording change cannot reclassify it.
import (
	"errors"
	"strings"
	"testing"

	"github.com/B-A-M-N/ocliv/internal/agent"
	"github.com/B-A-M-N/ocliv/internal/apperr"
)

// TestOwnershipDenialHintIsActionable pins the hint: it must name the
// name, the other key, and the action.
func TestOwnershipDenialHintIsActionable(t *testing.T) {
	err := agent.Permanent(errors.Join(agent.ErrLeaseOwnership,
		errors.New("publication name is held by a different agent key in this tenant")))
	code, hint := runnerExit(err)
	if code != apperr.ExitAuth {
		t.Fatalf("ownership denial exit=%d, want %d", code, apperr.ExitAuth)
	}
	lower := strings.ToLower(hint)
	if !strings.Contains(lower, "--name") {
		t.Fatalf("the ownership hint gives no corrective action: %q", hint)
	}
	if !strings.Contains(lower, "different") && !strings.Contains(lower, "another") {
		t.Fatalf("the ownership hint does not say who holds the name: %q", hint)
	}
	// It must NOT tell the operator to re-enroll: the credential is fine.
	if strings.Contains(lower, "re-enroll") || strings.Contains(lower, "login") {
		t.Fatalf("the ownership hint wrongly suggests re-enrollment: %q", hint)
	}
}

// TestCredentialDenialKeepsTheReenrollHint pins that the OTHER terminal
// class still gets its own advice: the two denials must not be confused.
func TestCredentialDenialKeepsTheReenrollHint(t *testing.T) {
	err := agent.Permanent(errors.New("agent lease permanently denied by relay"))
	code, hint := runnerExit(err)
	if code != apperr.ExitAuth {
		t.Fatalf("credential denial exit=%d, want %d", code, apperr.ExitAuth)
	}
	if !strings.Contains(hint, "re-enroll") {
		t.Fatalf("the credential denial lost its re-enroll hint: %q", hint)
	}
}

// TestOwnershipSentinelIsNotOtherDenials pins that the sentinel matches
// ONLY the ownership denial: a plain credential denial, a protocol
// mismatch, and a reachability failure must not pick up the ownership
// advice.
func TestOwnershipSentinelIsNotOtherDenials(t *testing.T) {
	cases := []error{
		agent.Permanent(errors.New("agent lease permanently denied by relay")),
		errors.New("protocol_incompatible: relay speaks ocliv/2"),
		errors.New("dial tcp 127.0.0.1:1: connection refused"),
	}
	for _, err := range cases {
		if errors.Is(err, agent.ErrLeaseOwnership) {
			t.Fatalf("a non-ownership error matched the ownership sentinel: %v", err)
		}
	}
}
