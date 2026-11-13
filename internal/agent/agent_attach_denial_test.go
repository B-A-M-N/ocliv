package agent

// P1: the agent must treat an OWNERSHIP denial as terminal and actionable.
//
// The relay closes a denied attach with distinct websocket codes. Before
// this fix, only 4401 (terminal credential denial) and 4410
// (replacement-permitted expiry) had classes; everything else — including
// the cross-key ownership conflict — fell through to the generic retry
// path, so the publisher looped forever with "reconnecting" and never
// told the operator what to do.
//
// The contract pinned here:
//   - 4401  terminal, credential problem;
//   - 4409  retryable, an allocation race a retry can win;
//   - 4410  replacement-permitted (one stale-record drop, then retry);
//   - 4413  terminal, ownership problem: a DIFFERENT agent key in the
//          same tenant holds the name. A retry can never win it, so the
//          agent must stop and say so.
import (
	"errors"
	"strings"
	"testing"

	"ocliv/internal/protocol"
)

// TestAttachDenialClassification pins the class of every close code the
// relay uses for a denied attach.
func TestAttachDenialClassification(t *testing.T) {
	cases := []struct {
		code      int
		permanent bool
		replaces  bool
	}{
		{protocol.CloseCodeAttachDenied, true, false},
		{protocol.CloseCodeAttachConflict, false, false},
		{protocol.CloseCodeAttachExpired, false, true},
		{protocol.CloseCodeAttachOwnership, true, false},
	}
	for _, c := range cases {
		verdict := classifyAttachDenial(c.code)
		if c.permanent && verdict != attachDenialPermanent {
			t.Fatalf("close code %d: verdict=%v, want permanent", c.code, verdict)
		}
		if !c.permanent && verdict == attachDenialPermanent {
			t.Fatalf("close code %d: classified permanent, but it is retryable", c.code)
		}
		if c.replaces && verdict != attachDenialReplaceOnce {
			t.Fatalf("close code %d: verdict=%v, want replace-once", c.code, verdict)
		}
	}
}

// TestOwnershipDenialMessageIsActionable pins that the operator learns
// WHAT to do, not merely that something failed.
func TestOwnershipDenialMessageIsActionable(t *testing.T) {
	msg := attachDenialMessage(protocol.CloseCodeAttachOwnership)
	if msg == "" {
		t.Fatal("the ownership denial has no message")
	}
	lower := strings.ToLower(msg)
	if !strings.Contains(lower, "name") {
		t.Fatalf("ownership message does not name the thing that is held: %q", msg)
	}
	if !strings.Contains(lower, "different") && !strings.Contains(lower, "another") {
		t.Fatalf("ownership message does not say who holds it: %q", msg)
	}
	if !strings.Contains(lower, "--name") {
		t.Fatalf("ownership message gives no corrective action: %q", msg)
	}
}

// TestTerminalCredentialMessageStaysDistinct keeps the 4401 message
// separate: a revoked credential must not be reported as a name conflict.
func TestTerminalCredentialMessageStaysDistinct(t *testing.T) {
	cred := attachDenialMessage(protocol.CloseCodeAttachDenied)
	own := attachDenialMessage(protocol.CloseCodeAttachOwnership)
	if cred == own {
		t.Fatal("the credential denial and the ownership denial share a message")
	}
	if strings.Contains(strings.ToLower(cred), "--name") {
		t.Fatalf("the credential denial wrongly suggests --name: %q", cred)
	}
}

// TestOwnershipDenialCarriesTheTypedSentinel pins that the ownership
// denial is recognizable by TYPE (not by wording), so the CLI can map it
// to the right corrective action even if the message text changes.
func TestOwnershipDenialCarriesTheTypedSentinel(t *testing.T) {
	err := attachDenialError(protocol.CloseCodeAttachOwnership)
	if !errors.Is(err, ErrLeaseOwnership) {
		t.Fatalf("the ownership denial does not carry the sentinel: %v", err)
	}
	if !IsPermanent(err) {
		t.Fatal("the ownership denial is not permanent")
	}
	// The credential denial must NOT carry it.
	cred := attachDenialError(protocol.CloseCodeAttachDenied)
	if errors.Is(cred, ErrLeaseOwnership) {
		t.Fatalf("the credential denial wrongly carries the ownership sentinel: %v", cred)
	}
}
