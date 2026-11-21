// Package apperr defines Ocliv's explicit error taxonomy and CLI exit codes.
package apperr

import "errors"

// Exit codes per production spec section 2.2.
const (
	ExitOK            = 0
	ExitCleanShutdown = 0
	ExitCLIValidation = 2
	ExitLocalTarget   = 3
	ExitAuth          = 4
	ExitRelayTLS      = 5
	ExitProtocol      = 6
	ExitQuotaLease    = 7
	ExitInternal      = 8
)

// Code is a stable machine-readable fault classification.
type Code string

const (
	CodeCLIValidation Code = "cli_validation"
	CodeLocalUnreach  Code = "local_unreachable"
	CodeEnrollAuth    Code = "enrollment_auth"
	CodeRelayUnreach  Code = "relay_unreachable"
	CodeTLSVerify     Code = "tls_verify"
	CodeProtocol      Code = "protocol_incompatible"
	CodeQuotaLease    Code = "quota_lease_denied"
	CodeInternal      Code = "internal"
	CodeVisitorAuth   Code = "visitor_auth_required"
	CodeVisitorForbid Code = "visitor_forbidden"
	CodeBadHost       Code = "bad_host"
	CodeUnknownHost   Code = "unknown_host"
	CodeBadRequest    Code = "bad_request"
	CodeUpstreamDial  Code = "upstream_dial"
	CodeUpstreamTO    Code = "upstream_timeout"
	CodeAgentOffline  Code = "agent_offline"
	CodeCapacity      Code = "capacity_exceeded"
	CodeSizeLimit     Code = "size_limit"
	CodeRateLimit     Code = "rate_limited"
	CodeStaleGen      Code = "stale_generation"
	CodeRevoked       Code = "revoked"
	CodeExpired       Code = "expired"
	CodeClosed        Code = "closed"
	CodeConflict      Code = "conflict"
	// CodeOwnershipConflict is a name held by a different owner: another
	// agent key in the same tenant, or another tenant. It is separated
	// from CodeConflict because the two have opposite retry semantics —
	// an allocation race is won by retrying, an ownership conflict never
	// is.
	CodeOwnershipConflict Code = "ownership_conflict"
	CodeStoreFault        Code = "store_unavailable"
	CodeCancelled         Code = "cancelled"
)

// Error is a typed Ocliv failure with a stable code.
type Error struct {
	Code Code
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// E builds a typed error.
func E(code Code, msg string, err error) *Error {
	return &Error{Code: code, Msg: msg, Err: err}
}

// CodeOf extracts the apperr.Code from err (unwrapping as needed), or returns
// "" if err is not an *apperr.Error.
func CodeOf(err error) Code {
	var ae *Error
	if errors.As(err, &ae) && ae != nil {
		return ae.Code
	}
	return ""
}

// ExitFor maps a fault code to a CLI exit status.
func ExitFor(code Code) int {
	switch code {
	case CodeCLIValidation, CodeBadRequest, CodeBadHost:
		return ExitCLIValidation
	case CodeLocalUnreach, CodeUpstreamDial:
		return ExitLocalTarget
	case CodeEnrollAuth, CodeVisitorAuth, CodeVisitorForbid, CodeRevoked, CodeClosed, CodeStaleGen:
		return ExitAuth
	case CodeRelayUnreach, CodeTLSVerify, CodeAgentOffline:
		return ExitRelayTLS
	case CodeProtocol:
		return ExitProtocol
	case CodeQuotaLease, CodeCapacity, CodeRateLimit, CodeSizeLimit, CodeConflict, CodeExpired:
		return ExitQuotaLease
	default:
		return ExitInternal
	}
}
