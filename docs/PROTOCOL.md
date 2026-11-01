# Ocliv relay — protocol deviations and strictness notes

Companion to `ocliv_invariants_and_exceptions_v1.md` (E-series) and
`ocliv_production_spec_v1.md`. This file records where the implementation
deliberately deviates from or sharpens the written spec, with rationale.
Amendments here carry the same weight as the spec clauses they cite.

## E01 amendment: deterministic single-parser path (authorized deviation)

Go's `net/http` consumes `Transfer-Encoding`/`Content-Length` into
`r.TransferEncoding`/`r.ContentLength` before handlers run. When TE is
present, `chunked` wins deterministically and any `Content-Length` is
dropped by the parser. Strict rejection of every TE+CL combination is
therefore unimplementable at the relay layer: by the time
`CheckRequestSyntax` runs, the ambiguous wire form no longer exists.

Authorized behavior (enforced in `internal/proxy/proxy.go`):

- TE present: exactly one `chunked` encoding is forwarded as a single
  unambiguous byte stream, which is never re-framed downstream, so no
  second parser can disagree. Any other TE value is rejected (400).
- No TE: duplicate `Content-Length` values must agree byte-for-byte;
  differing values are rejected (400).
- `CONNECT` and `TRACE` are rejected (400/405). Non-websocket `Upgrade`
  requests are rejected (400) by `CheckUpgradeSyntax`: an upgrade that is
  not a real protocol switch must not be forwarded as plain HTTP.
- Absolute-form request URIs are rejected.

The residual risk is parser disagreement *inside* Go's own parser, which
is outside this codebase's control; the relay never re-parses framing
it forwards.

## B10: version negotiation

The agent handshake carries `version`; the relay requires an exact match
with `protocol.Version` (401 otherwise). Unknown JSON fields are rejected
behind the version gate. A version bump is therefore a coordinated,
explicit break — never a silent downgrade.

## E12: trailers and interim responses

Responses that announce trailers the relay cannot deliver are rejected
(502) rather than silently dropped. Announced-trailer detection uses the
parsed trailer set, since Go consumes the `Trailer` header client-side.
