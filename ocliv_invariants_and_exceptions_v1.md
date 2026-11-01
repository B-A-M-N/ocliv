# Instant Tunnel — Invariants, Applicability, and Authorized Exceptions

**Companion to:** Instant Tunnel Production Specification v1.0 (2026-10-30)  
**Status:** Normative implementation contract, not evidence of implementation.  
**Scope:** Single-node Go relay behind Caddy; Go agent; authenticated WSS/yamux; HTTP/SSE/WebSocket to one explicitly chosen loopback port.  
**Key words:** MUST / MUST NOT are release-blocking; SHOULD is an operational recommendation.

## How to read this contract

- **U — Unconditional:** No supported configuration, reconnect, failure path, or administrator convenience bypasses the rule.
- **C — Conditional:** The rule has a defined precondition (e.g., private visitor auth, cookie-based browser request, live registered lease). When it does not hold, a *different explicit rule* applies. This is not permission to weaken anything else.
- **O — Explicit opt-in:** An owner or operator can select a documented alternative with bounded scope; it MUST NOT happen through fallback, heuristic inference, or environment drift.
- **N/A — Outside v1:** A request for an unsupported feature is rejected clearly; the system does not approximate it via an insecure path.

An **exception** is not a catch-all error handler. It specifies exactly **who may authorize it, under what condition, and which security constraints still apply**. Missing evidence, invalid state, unsupported conditions, and partial failure are **deny / unavailable / unknown**, never an implicit exception. In particular, `--public` bypasses *visitor authorization on that lease only*; it never bypasses agent identity, TLS, ownership, local-target restrictions, quotas, or auditing.

## A. Product, configuration, and user experience

| ID | Type | Invariant | Exception or scope boundary; required behavior |
|---|---|---|---|
| A01 | C | After enrollment and relay provisioning, `tunnel PORT` requires no DNS, certificate, router, or firewall edits on the agent host. | First-time account enrollment and self-hosted relay provisioning require explicit operator setup; do not advertise these as infrastructure-free. |
| A02 | U | An ordinary agent does not accept internet-initiated inbound connections. | None in v1; outbound connections only. Local HTTP service listens on loopback. |
| A03 | U | `tunnel PORT` accepts only a valid TCP port 1–65535 and resolves the destination deterministically. | Non-HTTP or unsupported target schemes fail validation; no guessed service discovery. |
| A04 | O | A default command opens a protected ephemeral tunnel. | Owner may choose `--public` for that lease; no remembered or inherited change of security default. |
| A05 | U | Startup, status, and `doctor` report only substantiated facts. | If local reachability, external DNS, TLS, or route probing cannot be established, print `unknown`, `unavailable`, or precise degraded status; never print an unverified green check. |
| A06 | U | CLI configuration precedence is explicit and stable; secrets never come from insecure implicit defaults. | Explicit flags > nonsecret environment > config > compiled hosted defaults; conflicting security flags fail instead of guessing. |
| A07 | U | CLI, JSON, process arguments, diagnostics, and logs do not expose secrets by default. | A share capability may be displayed once through an explicitly interactive secure output path; never in `--json`, logs, or process arguments. |
| A08 | U | Unsupported features fail with typed, actionable errors rather than silently approximating them. | Arbitrary TCP/UDP, LAN targets, generic open proxy, custom domains, and clustered HA are outside v1. |
| A09 | U | Exit codes and status transitions are stable and machine-readable. | During transient reconnect the process remains running and reports degraded state; it does not claim a clean exit. |

## B. Encryption, identity, and agent enrollment

| ID | Type | Invariant | Exception or scope boundary; required behavior |
|---|---|---|---|
| B01 | U | Every public visitor connection uses valid, hostname-verified HTTPS. | HTTP :80 may redirect to HTTPS; it may not carry application or tunnel credentials. No plaintext fallback. |
| B02 | U | The agent connects over TLS with certificate and relay-origin verification. | None; self-signed deployment requires an explicitly configured trusted CA, not `InsecureSkipVerify`. |
| B03 | U | External agent-to-relay tunnel traffic is encrypted and authenticated. | Loopback/Unix-socket traffic between Caddy and relay may be plaintext under local OS isolation; the operator relay is a trusted plaintext endpoint. Do not claim relay-opaque E2EE. |
| B04 | U | Only an enrolled, nonrevoked agent key may establish a data-plane session. | None; `--public` concerns visitors, not agents. |
| B05 | U | Agent enrollment requires an authorized, single-use or otherwise bounded enrollment grant. | Hosted account and self-hosted operator grants can differ, but unauthenticated public enrollment is prohibited. |
| B06 | U | The agent proves Ed25519 private-key possession through fresh, domain-separated challenge-response tied to relay, version, and lease intent. | None; possession of an IP, hostname, cookie, or header is not agent identity. |
| B07 | U | An authentication nonce is unpredictable, short-lived, consumed once, and checked against replay. | Clock skew may be accommodated only within a bounded verified window; excessive skew fails with a diagnostic. |
| B08 | U | Credentials at rest are limited to least-privileged files/storage; key material and signing secrets never appear in logs. | OS keychain optional; headless Linux secure-file fallback allowed. Unreadable/unsafe key file fails closed. |
| B09 | U | Revoked identities cannot create, renew, or resume a lease. | None. A temporary database failure cannot permit cached credentials to renew outside the chosen authorization policy. |
| B10 | U | Protocol incompatibility, unnegotiated security feature, or unknown required field fails closed. | Documented additive, optional fields may be ignored only after successful compatible feature negotiation. |
| B11 | U | Wildcard TLS certificate and signing-key lifecycle is explicitly monitored and renewed before expiry. | Certificate authority or DNS outage causes degraded/unavailable status, not HTTP fallback; already-valid certs may continue working until expiry. |

## C. Visitor authorization and browser security

| ID | Type | Invariant | Exception or scope boundary; required behavior |
|---|---|---|---|
| C01 | O | A protected lease authorizes every visitor request **before** allocating a forwarding stream or dialing localhost. | Owner explicitly selects `--public` for that lease; all other security checks remain. |
| C02 | U | Knowledge or guessing of the public hostname is never considered proof of visitor identity. | None; random names reduce discovery but are not authentication. |
| C03 | U | Agent identity, relay operator identity, visitor identity, and application identity are separate security domains. | None; app `Authorization` headers do not authenticate the tunnel and tunnel tokens do not authenticate the app. |
| C04 | C | API clients authenticate to protected leases using a relay-owned scoped credential, e.g. `X-Tunnel-Authorization`. | Public lease needs no visitor credential; application-specific credentials still pass untouched except reserved relay credentials. |
| C05 | C | Browser unlock converts an expiring capability to a host-only `Secure`, `HttpOnly` session cookie on a relay-controlled page. | CLI/API clients use header tokens; a non-JavaScript access-code path may be provided. No token in ordinary URL query parameters. |
| C06 | U | Visitor tokens are CSPRNG-generated, scope-bound, expiry-bound, revocable, and stored as one-way verifiers. | None; persistent named hostname does not imply persistent visitor credentials. |
| C07 | C | One-use share links cannot be redeemed more than once and cannot silently exceed expiry or scope. | A deliberately configured multi-use token may be issued by an authorized owner, with explicit use-count/expiry and revocation. |
| C08 | C | Unsafe cookie-authenticated browser methods require exact same-origin evidence or an independently verified CSRF proof. | Non-browser clients using a valid dedicated tunnel header may omit Origin; public endpoints enforce application-level CSRF rather than protected relay-cookie auth. |
| C09 | C | Protected WebSocket handshakes authorize before `101`; cookie-authenticated browsers additionally pass exact Origin validation. | Header-authenticated non-browser clients may omit Origin; public endpoint needs application-level WebSocket origin policy. Explicit origin allowlists must be per-lease and owner-authorized. |
| C10 | U | Rotation/revocation invalidates relevant tokens, cookies, sessions, and active protected streaming connections within a bounded revocation interval. | No grace for explicitly revoked access. Already-committed upstream side effects cannot be rolled back. |
| C11 | U | Relay unlock endpoints and credential cookies are reserved and cannot be served or overwritten by a tenant application. | None in v1; `/_tunnel/` is not forwarded. |
| C12 | U | Sharing an unlock link is treated as sharing a bearer secret, not as public-mode enablement. | No exception; leaked links must be revocable. Browser fragments reduce incidental leakage, not all leakage or XSS risk. |

## D. Hostname, tenant, and local destination isolation

| ID | Type | Invariant | Exception or scope boundary; required behavior |
|---|---|---|---|
| D01 | U | Each accepted public host maps to exactly one owning tenant, lease, and current session generation. | Offline, expired, suspended, unregistered, or ambiguous host maps to **no** forwarding destination. |
| D02 | U | HTTP Host, TLS SNI, and namespace syntax are strictly validated and correlated before lease resolution. | Protocol-specific absence of SNI is rejected for the public TLS listener; direct internal probes use a separate nonpublic route. |
| D03 | U | There is no default tenant/upstream fallback for unmatched or malformed hostnames. | None. Return an appropriate 400/404/421 and do not probe another tenant. |
| D04 | U | Hostname allocation, renewal, reassignment, and revocation require owner authorization and atomic conflict checks. | Operator takedown can suspend/revoke after audited authority verification; may not silently transfer ownership. |
| D05 | C | Ephemeral random hostnames have adequate CSPRNG entropy and are never allocated to an unrelated owner after retirement. | Owner-locked persistent named hosts may be reused by the same owner under a separate named-host lifecycle; names still require uniqueness and ownership. |
| D06 | O | Agent forwards only to the single configured literal loopback address and selected port for that lease. | `--ipv6` may explicitly select `::1`; other private/LAN hosts, Unix sockets, DNS names, and metadata endpoints are not supported in v1. |
| D07 | U | A public HTTP request cannot change the target host, port, path interpretation policy, lease, or agent key. | Owner restarting with a new local port requires explicit lease update or new invocation, with generation fencing; no client-driven reroute. |
| D08 | U | Relay strips attacker-supplied forwarded/proxy identity headers and reconstructs trusted metadata from its verified ingress. | A trusted edge proxy may provide identity information only over the configured authenticated/local ingress with strict proxy-chain validation. |
| D09 | O | Upstream `Host` is explicitly set to the expected local service authority. | `--upstream-host` is a documented agent-owner override; it cannot change the TCP dial destination or relay public routing. |
| D10 | U | The tunnel transport never follows application redirects or opens secondary network destinations. | Visitor browser may follow a returned `Location`, as normal HTTP behavior; that does not cause the agent to fetch it. |
| D11 | U | No HTTP CONNECT, arbitrary Upgrade, open-proxy, filesystem, or server-side URL fetch facility is created by tunneling. | WebSocket Upgrade is supported only through the validated WebSocket path; arbitrary TCP/UDP are later separate products/policies. |

## E. HTTP correctness, streaming, and multiplexing

| ID | Type | Invariant | Exception or scope boundary; required behavior |
|---|---|---|---|
| E01 | U | Public HTTP is parsed and normalized before transmission; no unvalidated raw HTTP message is forwarded across trust boundaries. | None. Invalid/conflicting CL/TE, malformed headers, unsupported CONNECT/Upgrade, or smuggling patterns fail closed. |
| E02 | U | Every multiplexed stream is bound to one request ID, lease, authenticated owner, and current generation. | None; request IDs are correlation values, not authority. |
| E03 | U | Control messages and data frames are length-bounded and versioned; lengths are validated before allocation. | Negotiated optional features can add frame types only with compatible explicit version/capability checks. |
| E04 | U | Distinct concurrent requests cannot cross-wire body bytes, response headers, cookies, stream close, or identities. | None; no shared mutable per-request state without correct isolation. |
| E05 | U | Request and response bodies are streamed using bounded buffers and backpressure, not whole-body buffering. | A small bounded buffer is allowed; bounded administrative error pages may be generated locally. |
| E06 | U | Cancellation propagates both ways and eventually releases local sockets, streams, and goroutines. | Local app cannot be forced to reverse already-committed work; if transport fails, cleanup must still occur. |
| E07 | U | Incoming application headers and cookies are preserved unless explicitly hop-by-hop, relay-reserved, unsafe, or spoofed. | Rewrite only with a documented compatibility flag/policy; never silently strip app Authorization or cookies. |
| E08 | U | Relay credentials and internal control metadata never reach the local application. | None, including `--public` mode. |
| E09 | U | A local service response is not silently altered to claim a different method outcome, body, status, or success. | Explicitly reserved relay-generated errors are distinguishable from app responses; normal HTTP hop-by-hop transformations are allowed. |
| E10 | C | WebSocket public `101` is completed only after authentication, route validation, and successful local WebSocket handshake. | Ordinary HTTP and SSE do not use a `101` upgrade; unsupported Upgrade types are rejected. |
| E11 | U | SSE and bidirectional streams flush incrementally and remain subject to backpressure/cancellation. | A nonstreaming finite response may be buffered only within fixed limits; never buffer an unbounded SSE until close. |
| E12 | U | A failed or unknown special protocol semantic is explicit, never silently approximated. | `100 Continue`, `103 Early Hints`, and trailers may be supported when interoperably tested; otherwise deterministic rejection where feasible, not corruption. |
| E13 | U | A response already committed to an HTTP client cannot be replaced with an unrelated new status after later failure. | Close/abort the stream and record the partial-delivery outcome. |
| E14 | U | No automatic replay of any request whose arrival or execution at the application is uncertain. | A request proven never dispatched may be retried by a separately defined safe mechanism; app-managed idempotency is caller/application responsibility. |
| E15 | U | One congested stream does not consume unbounded memory or serialize all other streams at application level. | All streams share physical bandwidth/CPU; no per-stream guarantee of unaffected latency during link saturation. |

## F. Sessions, leases, reconnect, and failure semantics

| ID | Type | Invariant | Exception or scope boundary; required behavior |
|---|---|---|---|
| F01 | U | Lease state transitions follow an explicit, validated state machine. | Crash recovery can reconcile durable state into `RECONNECTING`, `EXPIRED`, or `REVOKED`, never invent `ACTIVE` without live evidence. |
| F02 | U | There is exactly one active, authoritative session generation per lease. | Different independent leases may have concurrent sessions; older generation never accepts new requests. |
| F03 | U | Every successful resume advances fencing generation atomically. | None; stale generations are rejected even after old control frames arrive late. |
| F04 | C | An owner may reclaim the same ephemeral hostname during its valid reconnect grace. | After grace/expiry, new invocation gets a new ephemeral name; named hosts remain owner-reserved but are not automatically live. |
| F05 | C | A reconnect resumes the existing lease only after key ownership, expiry, revocation, and version checks succeed. | No valid resume proof = reject or create a *new, separately authorized* lease; never hijack the old URL. |
| F06 | U | Relay marks a route `ACTIVE` only if a live authenticated session exists and local readiness conditions have passed. | A valid local HTTP `401`/`404` may prove listener responsiveness if configured probe expects it; no universal requirement that GET `/` returns 200. |
| F07 | U | Offline, reconnecting, draining, or expired routes cannot silently deliver new requests to stale sockets. | In-flight requests from the old generation may drain for a short bounded interval only when not revoked and with explicit policy; revocation terminates them. |
| F08 | U | Timeouts and transient failures produce truthful typed outcomes. | Before headers: appropriate 502/503/504; after headers: terminate/abort, not fabricated replacement status. |
| F09 | U | Reconnection is bounded exponential backoff with jitter; no tight reconnect loops. | On permanent credential/protocol revocation, stop retries and require corrective action. |
| F10 | U | Ctrl+C/SIGTERM attempt graceful drain, lease closure, and access revocation. | SIGKILL, crash, or power loss cannot execute cleanup; heartbeat expiry and persisted lease expiry are mandatory fallback. |
| F11 | U | A relay restart preserves durable ownership/revocation records and refuses traffic until agents reauthenticate. | Active socket objects are not persisted; temporary unavailability is expected. No false active route on restart. |
| F12 | U | Database corruption, unknown schema, failed migration, or unavailable authorization store fails closed. | Read-only diagnostic mode may remain available internally; new public forwarding cannot continue under unverified ownership. |
| F13 | U | A released hostname or session cannot be taken over through a late frame, delayed callback, or process race. | None; generation/version checks must happen at dispatch and state mutation boundaries. |

## G. Quotas, denial of service, and fairness

| ID | Type | Invariant | Exception or scope boundary; required behavior |
|---|---|---|---|
| G01 | U | All externally controlled resource use is bounded: headers, metadata, frames, streams, queue depth, body size, idle lifetime, and rate. | Operator may adjust limits within a documented safe cap; no unlimited mode. |
| G02 | U | Rate and admission controls execute before expensive stream creation or local socket dials. | None; a preauthorized public endpoint is still subject to quotas. |
| G03 | U | Each tenant/lease has independent counters, limits, and attributable resource consumption. | A single physical link or process capacity is shared; weighted fairness cannot create unused bandwidth. |
| G04 | U | Long-lived SSE/WebSocket connections use idle-progress and max-lifetime policies instead of a universal short request deadline. | Ordinary HTTP first-byte deadlines still apply; connections must not be immortal and unbounded. |
| G05 | U | Limits trigger deterministic errors/closure rather than queue explosion, deadlock, or partial cross-tenant delivery. | Response already committed -> close instead of injecting an HTTP error. |
| G06 | U | Slow-read, slow-write, stream flood, frame fragmentation, and malicious upgrade tests do not produce unbounded resource growth. | Performance may degrade under overload; acceptable outcome is bounded rejection/degradation, not uninterrupted SLA. |
| G07 | C | Authenticated enrollment and abuse/takedown controls precede opening the relay to arbitrary public tenants. | Private single-owner self-hosting need not include hosted-service billing/account UX; still enforces owner auth, quotas, and limits. |
| G08 | U | Metrics, cardinality, goroutines, file descriptors, and buffers are bounded and observable during sustained load. | Temporary bounded spikes during startup/shutdown are acceptable when measured and capped. |

## H. Operational security, observability, and release

| ID | Type | Invariant | Exception or scope boundary; required behavior |
|---|---|---|---|
| H01 | U | Only Caddy edge listeners are publicly accessible (HTTPS :443 and optional HTTP :80 redirect); relay administration, metrics, SQLite, and diagnostics remain private. | Explicit operator-only management access over authenticated protected channels is allowed; no unguarded public wildcard admin route. |
| H02 | U | Relay runs least-privileged with restricted writable paths, OS capabilities, and ingress firewall. | Provisioning may temporarily require root; the long-lived relay process must not. |
| H03 | U | Logs, metrics, crash reports, backups, and doctor outputs do not disclose body payloads or bearer credentials by default. | Explicit local operator diagnostic capture requires informed action, time/size bounds, and secure storage; payload capture is not v1 default. |
| H04 | U | Audit records distinguish enrollment, authorization, routing, revocation, policy changes, and security failures. | Avoid recording PII/full request paths merely for convenience; trace with opaque correlation IDs. |
| H05 | U | Operator and user status distinguish liveness, readiness, and externally proven reachability. | A green process liveness check never implies public routing works. DNS reachability can vary geographically and must be reported as tested. |
| H06 | U | Durable identity/lease state and TLS material have protected, tested backup and restoration procedures. | A single-node server can still have downtime; recovery is mandatory, hot failover is not claimed. |
| H07 | U | Deployment/migration and upgrade operations are idempotent and rollback-aware; existing secrets are not silently overwritten. | Explicit operator-authorized destructive reset may remove state, with acknowledged loss and revocation consequences; never implicit during retry. |
| H08 | U | Supported release builds have provenance/integrity checks and dependency/security review. | Development builds may be unsigned if clearly labeled nonproduction; they cannot satisfy production qualification. |
| H09 | U | No availability, end-to-end confidentiality, or performance SLA is claimed without matching measured/architectural evidence. | Single VPS has no active-active HA; public DNS/TLS/relay/internet failures can cause downtime. |
| H10 | U | Production qualification includes external client, adverse-network, adversarial security, chaos, race, fuzz, load, soak, and restore evidence. | A partial prototype may be labeled experimental; it must never be represented as production qualified. |

## M. MCP hosting security

V1 scope: an existing HTTP MCP server uses the ordinary secure forwarding
path (thin extension — no JSON-RPC parsing or rewriting in the tunnel).
M07/M08/M12 concern the V1.1 stdio adapter and management MCP, which do
not exist in v1; their rows state the prohibition that applies until then.
OAuth audience/issuer/expiry/scope validation (M04) is enforced by the
hosted MCP server; Ocliv's responsibility is opaque, unmodified
forwarding of application `Authorization` while always stripping its own
credentials. Public custom-connection compatibility is NOT VERIFIED until
tested with the actual provider and authentication flow (M15).

| ID | Type | Invariant | Exception or scope boundary; required behavior and proof |
|---|---|---|---|
| M01 | O | MCP tunnels are protected by default. | Owner may pass `--public` for that lease (A04/C01). Proof: default allocation is protected; unauthenticated JSON-RPC denied with zero app hits (`TestMCPOverOrdinaryForwardingPath`). |
| M02 | U | No implicit public-mode fallback. | Proof: resume with a changed access mode allocates a new lease, never inherits exposure (`relay_leases.go` mode fence + mode-change test). Unsupported auth configuration fails closed. |
| M03 | U | Ocliv credentials never reach hosted MCP tools. | Proof: `SanitizeVisitorHeaders` strips `X-Ocliv-Authorization`; adversarial spoof test + `TestMCPHeaderPreservation` (spoofed relay header absent upstream). |
| M04 | C | Upstream OAuth/Bearer [REDACTED] are audience- and scope-bound at the application boundary; Ocliv forwards them opaquely. | Precondition: upstream-authenticated deployment where the MCP server enforces OAuth. Ocliv MUST NOT validate, mint, or strip app `Authorization`. Proof: `TestMCPHeaderPreservation` (`app_auth` byte-identical upstream). Wrong-audience rejection is app-enforced; cross-endpoint token reuse is prevented by the app's audience check, with Ocliv guaranteeing the token it forwards is the one the client sent. |
| M05 | U | MCP forwarding preserves protocol semantics for the current (2026-07-28, stateless) and explicitly qualified legacy transports. | No session id required; legacy `Mcp-Session-Id` passes through untouched. Proof: `TestMCPHeaderPreservation` + JSON-RPC roundtrip (`TestMCPOverOrdinaryForwardingPath`) + SSE/WS suites. The obsolete session model is not a universal contract. |
| M06 | C | Invalid browser Origin cannot access cookie-authenticated MCP endpoints. | Browser (cookie) clients: exact same-origin or verified CSRF proof (C08/C09, `TestCSRFEnforcement`). Header-authenticated non-browser clients may omit Origin; Origin is preserved for the app's own policy. |
| M07 | U | Remote clients cannot select, launch, or parameterize local processes. | No stdio adapter exists in v1; product code contains no process-launch path for visitor input (AS-050). Any future adapter executes only operator-specified commands, never remote-supplied ones. |
| M08 | O | Hosted stdio processes, when the V1.1 adapter exists, run under restricted OS authority. | v1: N/A (no adapter; prohibited by default). Future adapter requires loopback-only, no shell, bounded resources, lifecycle binding, secret/filesystem isolation; OS-level confinement (dedicated user/systemd) is a deployment obligation, not in-tunnel code. |
| M09 | U | Client-specific MCP state cannot cross tenants or leases. | Proof: tenant-isolation suite (cross-lease denial, per-lease verifiers/generations). |
| M10 | U | Revocation terminates MCP access for new and in-flight calls within the bounded revocation interval. | Proof: revoke/rotate/takedown tests incl. active-stream termination (`TestRevokeTerminatesAccess`, `TestRevokeTerminatesWebSocket`, `TestOperatorTakedownPublicLease`). |
| M11 | U | No tool execution before authorization: an unauthorized request never opens a stream to the local process. | Proof: authorize-before-stream (C01, `relay_public.go`); denied MCP call produces zero app hits (`TestMCPOverOrdinaryForwardingPath`). |
| M12 | U | MCP management interfaces are local and opt-in only. | No management MCP exists in v1 (H01). Signed agent management requires the owner key and one-time nonces; remote/visitor callers cannot reach it (authority 421s). |
| M13 | U | MCP result sizes, concurrency, and lifetimes are bounded per lease with independent release paths. | Proof: limits/transport frame caps + quota suites (G01–G06). Cross-machine load/soak remains NOT VERIFIED. |
| M14 | U | Authentication failures never downgrade to anonymous or weaker access. | An explicit invalid credential is a hard 401 even when another credential would validate (no fallback). Proof: `relay_public.go` explicit-invalid path + `TestExplicitInvalidCredentialNoCookieFallback`. |
| M15 | U | Claims of client compatibility require live per-client evidence. | Local-loopback evidence is recorded in `docs/qualification/`; public provider interop (ChatGPT/custom connections) is NOT VERIFIED until exercised against the real provider and auth flow. Demo or docs MUST NOT imply otherwise (H05/H10). |

## Mode-specific exception matrix

| Mode / condition | Visitor auth | Agent identity | Public TLS | Exact loopback target | Host/tenant lease ownership | Quotas and cancellation |
|---|---|---|---|---|---|---|
| Default `tunnel 3000` | **Required** | Required | Required | Required | Required | Required |
| Explicit `--public` | **Intentionally bypassed for visitors only** | Required | Required | Required | Required | Required |
| Browser share link | Required, via redeem + cookie | Required | Required | Required | Required | Required |
| API visitor bearer token | Required, via header | Required | Required | Required | Required | Required |
| Reconnecting/offline | No forwarding | Resume auth required | No insecure fallback | Bound target retained | Owner retained | Required |
| Owner revokes access | Forwarding denied/active access closed | Required for session | Required | Required | Retained until lease closure | Required |
| Relay or authorization DB failure | No unverified forwarding | Cannot bypass | No fallback | No fallback | Cannot guess ownership | Fail closed |
| IPv6 loopback opted in | Same as mode | Required | Required | `::1` only | Required | Required |
| Operator bootstrap | No public app route until qualified | Enrollment grant required | ACME/DNS setup in progress | N/A until agent attaches | Reserved namespace | Setup controls required |

## Exceptions that are **not** allowed

1. A public tunnel does **not** authorize anonymous agents, arbitrary targets, unrestricted request volumes, or plaintext connections.
2. A reconnect does **not** authorize a different agent key, expired lease, revoked user, stale generation, or reallocated hostname.
3. Successful TCP dial does **not** prove HTTP/HTTPS endpoint readiness. HTTP 200 on a health path is not universally required either.
4. A valid TLS certificate does **not** prove visitor authorization, local app security, or end-to-end encryption against the relay.
5. Local application `Authorization` does **not** substitute for relay access controls, and relay access credentials never become application auth.
6. A successfully sent HTTP request does **not** prove that the local app committed it; a missing response cannot be auto-replayed safely.
7. Streaming and WebSockets do **not** exempt a connection from quotas, expiry/revocation, idle detection, or cancellation.
8. A single-node relay's memory cannot replace durable owner/revocation state after restart.
9. `--debug`, `--json`, and `doctor` do **not** authorize automatic secret disclosure or request/response body capture.
10. Admin urgency and malformed client traffic do **not** justify falling back to insecure modes.

## Formal acceptance rule for each invariant

For each ID implement (a) a responsible module and enforcement location; (b) a positive test demonstrating the rule; (c) a negative or falsification test demonstrating rejection; (d) an exception-specific test when an exception exists; and (e) a concrete runtime diagnostic/counter for observable failures. Do not declare an invariant satisfied because a configuration value is present, a unit test mocks the critical boundary, or one component claims success. Evidence must reach the relevant public/agent/relay boundary.

**Release decision:** Every unconditional (`U`) invariant must have passing evidence. Every conditional (`C`) rule must pass when its precondition is met and must demonstrate its separate alternative behavior when not met. Every opt-in (`O`) path must require explicit authority and preserve all surrounding unconditional invariants. A failing or untested security invariant blocks production release; an out-of-scope feature must be rejected, not represented as partially supported.
