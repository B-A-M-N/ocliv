package agent

// Attach-denial classification (agent side).
//
// The relay closes a denied attach with a code that says what the denial
// MEANS. The agent's job is to act on that meaning instead of looping:
//
//	4401 terminal credential denial — the identity is revoked or unknown.
//	     A retry can never fix it, so the agent stops.
//	4409 allocation race — two publishers raced for a lease. Retryable
//	     with backoff; a retry can win it.
//	4410 expired lease — the lease expired under this identity. One
//	     stale-record drop and one reconnect are permitted.
//	4413 ownership conflict — the requested NAME is held by another agent
//	     key (or another tenant). Terminal: no retry can win a name this
//	     publisher does not own, so the agent stops and tells the operator
//	     what to change.
//
// Before this split, every code except 4401 fell through to the generic
// retry path, so a cross-key conflict produced an endless "reconnecting"
// loop with no actionable message.
import (
	"errors"
	"fmt"

	"ocliv/internal/protocol"
)

// ErrLeaseOwnership marks the terminal denial an agent receives when the
// requested publication name belongs to a different agent key (or a
// different tenant). It is a TYPED sentinel, not a message convention:
// the CLI maps it to its own corrective action, and a wording change can
// never silently reclassify the failure.
var ErrLeaseOwnership = errors.New("lease ownership conflict")

// attachDenialVerdict is the agent's decision for one close code.
type attachDenialVerdict int

const (
	// attachDenialRetry means: keep retrying with backoff.
	attachDenialRetry attachDenialVerdict = iota
	// attachDenialPermanent means: stop; a retry cannot fix this.
	attachDenialPermanent
	// attachDenialReplaceOnce means: drop the stale local record and
	// reconnect exactly once for a fresh lease.
	attachDenialReplaceOnce
)

// classifyAttachDenial maps a relay attach-denial close code to the
// agent's verdict. An unknown code is treated as retryable, matching the
// historical behavior for codes this agent does not model; the codes the
// relay actually sends are all classified above.
func classifyAttachDenial(code int) attachDenialVerdict {
	switch code {
	case protocol.CloseCodeAttachDenied:
		return attachDenialPermanent
	case protocol.CloseCodeAttachExpired:
		return attachDenialReplaceOnce
	case protocol.CloseCodeAttachOwnership:
		return attachDenialPermanent
	default:
		return attachDenialRetry
	}
}

// attachDenialMessage is the operator-facing text for a denial class.
// It must name the thing to change, not merely report that something
// failed: the ownership message in particular has to tell the operator
// which knob to turn.
func attachDenialMessage(code int) string {
	switch code {
	case protocol.CloseCodeAttachDenied:
		return "agent lease permanently denied by relay"
	case protocol.CloseCodeAttachOwnership:
		return "publication name is held by a different agent key in this tenant: " +
			"publish under a different --name, or ask the operator to transfer or revoke the existing one"
	case protocol.CloseCodeAttachExpired:
		return "agent lease expired; reconnecting once for a fresh lease"
	case protocol.CloseCodeAttachConflict:
		return "lease allocation conflict; retrying"
	default:
		return ""
	}
}

// attachDenialError renders a denial as an error, wrapped as permanent
// when the class says no retry can fix it. The ownership denial carries
// the typed sentinel so the CLI can map it to its own corrective action
// without matching on message wording.
func attachDenialError(code int) error {
	msg := attachDenialMessage(code)
	if msg == "" {
		return fmt.Errorf("no session attach: relay closed with code %d", code)
	}
	if code == protocol.CloseCodeAttachOwnership {
		return Permanent(fmt.Errorf("%w: %s", ErrLeaseOwnership, msg))
	}
	if classifyAttachDenial(code) == attachDenialPermanent {
		return Permanent(fmt.Errorf("%s", msg))
	}
	return fmt.Errorf("%s", msg)
}
