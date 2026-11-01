// Package apperr defines Ocliv's explicit error taxonomy and CLI exit codes.
package apperr

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
	CodeConflict      Code = "conflict"
	CodeStoreFault    Code = "store_unavailable"
	CodeCancelled     Code = "cancelled"
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

// ExitFor maps a fault code to a CLI exit status.
func ExitFor(code Code) int {
	switch code {
	case CodeCLIValidation, CodeBadRequest, CodeBadHost:
		return ExitCLIValidation
	case CodeLocalUnreach, CodeUpstreamDial:
		return ExitLocalTarget
	case CodeEnrollAuth, CodeVisitorAuth, CodeVisitorForbid, CodeRevoked, CodeStaleGen:
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
