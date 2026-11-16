# MCP readiness evidence

MCP readiness is a set of separate claims. A successful check proves only
its named facet and vantage point; it does not promote another facet to
verified.

| Facet | Evidence required | Current owner |
|---|---|---|
| Local protocol | Negotiated MCP session and valid `tools/list` reply | `ocliv mcp publish` local probe; `mcp doctor` |
| Resource discovery | Exact route resource URL and matching authorization-server issuer | Go publisher before activation; `verify-ingress.sh` at the public route |
| Upstream authorization | Missing and invalid bearer both rejected; valid token separately proves protocol access | Go publisher local probe; public `verify-ingress.sh` |
| Managed authorization | Relay challenge and approved client access on the exact route | Managed-auth qualification procedure |
| Publisher-vantage route | Public URL returns the expected unauthenticated `401` challenge from the publisher's host | Skybridge `probeRoute`; this does not prove MCP execution |
| Authenticated protocol | Valid bearer receives a valid `tools/list` response | `verify-ingress.sh` |
| Authenticated execution | Valid bearer completes a harmless tool call with no JSON-RPC or MCP tool error | `verify-ingress.sh` |
| Off-LAN reachability | Exact route tested from a device outside the LAN and tailnet | Operator qualification |
| Hosted-assistant acceptance | OAuth completes and a harmless tool call succeeds in the intended assistant | Operator-controlled acceptance |

The release receipt is tied to the HTTPS `/r/<route-id>/mcp` URL, exact
source revision, and qualified binary SHA-256. It records protected-resource
metadata, the exact route authorization-server issuer, missing and invalid
bearer rejection, authenticated `tools/list`, and successful authenticated
tool execution. `verify-ingress.sh` signs the receipt with the operator-held
key; the release builder verifies the detached signature and all three
identity bindings, then rejects a missing, stale, mismatched, or incomplete
receipt. This signed evidence still does not prove off-LAN reachability or
hosted-assistant acceptance.

The Skybridge publisher's `readiness` object is deliberately narrower. Its
`401` probe proves only publisher-vantage route reachability and missing-bearer
rejection; its remaining facets stay false until a stronger verifier supplies
the required evidence. A green publisher probe is not an off-LAN or release
qualification.

Production promotion remains gated on the exact candidate artifact, operator
approval, and the separate production-state and off-LAN checks in the runbook.
