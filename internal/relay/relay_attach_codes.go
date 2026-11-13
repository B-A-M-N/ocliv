package relay

// Attach-denial close-code mapping (relay side).
//
// The relay and the agent must agree on what a denial MEANS, because the
// agent's retry decision is derived from the close code alone:
//
//	4401 terminal credential denial — a retry can never fix it;
//	4409 allocation race — retryable, a retry can win it;
//	4410 expired lease — one stale-record drop, then one reconnect;
//	4413 ownership conflict — the name belongs to another key or tenant;
//	     terminal, because no retry can win a name this publisher does
//	     not own.
//
// The mapping lives here so the wire contract has a single source of truth
// and the agent cannot drift from it.
import (
	"ocliv/internal/apperr"
	"ocliv/internal/protocol"
)

// attachCloseCode maps an allocation/resume denial to the websocket close
// code the agent classifies. Anything unrecognized is terminal (4401):
// an unknown denial reason must never become an infinite retry loop.
func attachCloseCode(err error) int {
	var ae *apperr.Error
	if !asApperr(err, &ae) {
		return protocol.CloseCodeAttachDenied
	}
	switch ae.Code {
	case apperr.CodeConflict:
		return protocol.CloseCodeAttachConflict
	case apperr.CodeExpired:
		return protocol.CloseCodeAttachExpired
	case apperr.CodeQuotaLease:
		return protocol.CloseCodeAttachQuota
	case apperr.CodeOwnershipConflict:
		return protocol.CloseCodeAttachOwnership
	default:
		return protocol.CloseCodeAttachDenied
	}
}
