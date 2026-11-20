# Instant Tunnel — Production Specification

**Status:** Implementation-ready design, not an assertion that the product has been implemented or tested.  
**Version:** v1.0 design baseline, 2026-10-30  
**Product category:** Self-hostable localhost-to-public-HTTPS tunnel  
**Primary command:** `tunnel 3000`  
**Implementation language:** Go

---

## 0. Product contract

The program opens an outbound authenticated, encrypted session from a local machine to a public relay, registers a short-lived HTTPS hostname, and forwards HTTP/1.1-compatible request/response traffic (including WebSockets and server-sent events) to exactly one local loopback port. No incoming ports or firewall changes are needed on the agent machine.

**Success is observable, not merely asserted.** The CLI prints a public hostname only after the relay has acknowledged the registration and verified that it can route an authenticated probe through the tunnel to a responsive local service. If a TCP listener exists but an HTTP service does not answer a probe, report the discrepancy; do not claim full HTTP readiness. The relay’s readiness to accept a connection does not guarantee global DNS propagation; setup verifies external DNS independently.

### Three supported operating modes

1. **Hosted relay:** An operator maintains a shared relay and domain. End users install a preconfigured binary, enroll once, and then run `tunnel 3000` without DNS/VPS configuration. For a hosted multi-tenant service, enrollment, quotas, and abuse response are mandatory; unlimited unauthenticated registration is out of scope.
2. **Personal self-hosted relay:** The operator installs a relay on a public VPS and configures DNS/TLS once. Local agents enroll once, then use `tunnel 3000`. No commercial hosted service dependency is required after installation. Running `tunnel 3000` with *literally no* prior knowledge of a relay is possible only if an opinionated default hosted service is supplied.
3. **Deliberately public endpoint:** `tunnel 3000 --public` bypasses the relay’s visitor authentication for that particular lease. It never bypasses agent identity, routing ownership, rate limiting, or resource quotas. The CLI prints an exposure warning.

### Explicit non-goals for v1

Arbitrary TCP/UDP forwarding, SSH/RDP tunneling, QUIC transport, SSH reverse tunnels, custom domains, Kubernetes, GUI dashboard, agent orchestration, distributed consensus, HTTP request inspection/storage, edge functions, generic SSRF/open proxying, and transparent zero-knowledge encryption against the relay.

---

## 1. Security and trust model

### 1.1 Mandatory trust boundaries

- The **visitor** is untrusted, even when they know the hostname.
- The **application** behind `127.0.0.1:PORT` may have vulnerable or administrative endpoints; an authenticated visitor still receives the authority the application exposes.
- The **agent** is trusted only to connect to a service on the owning machine’s explicitly selected loopback port. A visitor cannot choose arbitrary destination hostnames, IP addresses, file paths, or ports.
- The **relay** is trusted for routing, authentication, rate limits, and correct isolation. It sees plaintext between public HTTPS termination and the local forwarding hop. Advertise TLS-on-each-network-hop, not end-to-end encryption opaque to the relay.
- The **relay operator** can change routing or read data if the machine is compromised. Strong private operations are required, but this design cannot eliminate this trust.
- The **DNS provider** and **certificate authority** are trusted for public domain control. Compromise of the wildcard TLS key affects the whole tunnel namespace.

### 1.2 Default-deny exposure

`tunnel 3000` defaults to **protected**. Authentication happens before the relay opens a stream to the agent. The public hostname is not a secret and random subdomains do not count as authorization. The optional mode `--public` is an affirmative, auditable choice. Always label the active mode in the CLI.

### 1.3 Separate agent identity from visitor access

**Agent identity:** On first enrollment, generate an Ed25519 keypair with a system CSPRNG. Store the private key with owner-only permissions (0600 on Unix), never in logs. The relay stores the public key, account/tenant owner, status, quotas, and revocation state. Enrollment requires an operator-issued one-time enrollment credential or hosted account authorization. Challenge-response over verified TLS proves possession of the key and binds the session to the relay origin, protocol version, key ID, nonce, timestamp, and requested lease. Relay nonces are short-lived and one-time-use. Never use a hostname, IP, or `Origin` header as a client credential.

**Visitor authentication:** Protected tunnels use an independent random 256-bit access secret. Store only a one-way verifier (hash or HMAC with appropriately protected server key) and optionally an identifier, never the raw secret in the relay database. An ephemeral protected tunnel may issue a scoped share token; visitor sessions are issued only after server-side verification. Token rotation and tunnel revocation invalidate active sessions as well as future logins.

**Browser usability:** Print a normal HTTPS URL and generate a protected share link pointing to a relay-owned unlock page with the token carried in a URI **fragment** (`#...`) rather than a query parameter. The share link is an explicit convenience tradeoff: the browser temporarily holds a bearer secret, so users should still treat it as confidential and revoke it after accidental disclosure. The token does not cross the network in the browser’s initial HTTP request; first-party JavaScript reads it, exchanges it via a same-origin `POST`, immediately removes it from browser history, then receives an `HttpOnly; Secure; SameSite=Lax; Path=/` host-only session cookie (prefer the `__Host-` prefix). This is a bearer capability: anyone receiving the share link can redeem it until it expires/revokes. An optional one-time/short-lived share link is preferable. Support a non-JavaScript access-code form. The login page must use a strict CSP, no third-party scripts, no external resources, no analytics, `Cache-Control: no-store`, and `Referrer-Policy: no-referrer`.

**API/CLI visitors:** Accept `X-Tunnel-Authorization: Bearer <scoped-token>` over HTTPS. This dedicated relay-owned header avoids colliding with the local application’s separate `Authorization` header. Never accept tunnel access tokens in ordinary query parameters, access logs, redirect targets, or the headers forwarded to the local app. Return `401` with an explicit `X-Tunnel-Auth-Required: true` signal to API callers. Consume and strip relay authentication headers and the reserved relay cookie before forwarding; preserve the application’s unrelated cookies and `Authorization` header. Document this contract and do not silently treat the app’s bearer token as the tunnel access credential.

**Cookie-authenticated browser requests:** For unsafe HTTP methods (POST, PUT, PATCH, DELETE, etc.), enforce an exact-match `Origin` check against the tunnel origin; reject hostile, `null`, or absent Origin unless a documented equivalent CSRF proof is supplied. Do not rely on `SameSite=Lax` alone: different tenants on `*.t.example.com` are cross-origin but can be same-site. For non-browser tools that need to make such requests, accept the dedicated tunnel token header instead of relying on cookies. A user application remains responsible for its own CSRF defenses, and a state-changing GET endpoint remains unsafe regardless of this boundary.

**WebSocket visitors:** The same visitor authorization is required during the HTTP upgrade handshake. For cookie-authenticated browser upgrades require `Origin` to exactly match the active HTTPS tunnel origin; reject `null`/cross-origin and malformed origins unless an explicit per-tunnel allowlist is configured. For `--public`, the local application remains responsible for its WebSocket origin authorization. For non-browser callers without `Origin`, require a valid dedicated authorization credential when private.

### 1.4 Restrict local destinations

- Accept a **port number** 1–65535, not arbitrary URLs, as the primary CLI argument.
- Resolve the upstream to a literal `127.0.0.1:PORT` by default, with a documented `--ipv6`/`[::1]` option; do not resolve arbitrary DNS names. Do not use an environment HTTP proxy for local dials.
- Deny access to other ports, Unix sockets, private LANs, metadata addresses, Docker socket, and arbitrary outbound connections in v1.
- No HTTP redirect following inside the agent’s forwarding transport; remote application redirects are sent to the visitor, not followed by the agent.
- Ensure backend `Host` is intentionally set. Default local upstream Host is `127.0.0.1:PORT`, while trustworthy `X-Forwarded-Host`/`X-Forwarded-Proto=https` convey the public origin. Provide `--upstream-host` for frameworks that require explicit public-host support. Strip untrusted inbound `Forwarded` and all `X-Forwarded-*` variants before reconstructing authoritative fields at the relay.
- No implicit proxy from the relay to a user-provided private-network target.

### 1.5 Defense-in-depth

- Strict external HTTPS; do not bypass TLS verification (`InsecureSkipVerify` prohibited).
- Fresh random tunnel identifiers (at least 80 unpredictable bits in the hostname suffix) and non-recycled hostnames; hostname lease is bound to owner public key and generation (fencing epoch).
- Enforce exact `Host` allowlist and public SNI/Host consistency; reject malformed, nested, internationalized, misleading or suffix-confusable hostnames. Public host routing never falls back to an operator default app.
- Reject ambiguous HTTP parsing: duplicate/conflicting `Content-Length`, `Transfer-Encoding` smuggling variants, malformed header bytes, invalid CONNECT/absolute URI forms, unsupported Upgrade protocols, and invalid hop-by-hop header declarations. Never route raw unvalidated HTTP request bytes directly to the agent.
- Independent rate limits on registration, authentication, hostname allocation, incoming connections, bandwidth, concurrency, and repeated failures. Deny before allocating expensive per-stream state.
- Bounded header size, body size, active stream count, WebSocket lifetime and idle time; streamed bodies and backpressure rather than memory buffering. Prevent one slow stream from blocking unrelated streams.
- Never log request bodies, response bodies, secrets, cookies, `Authorization`, private keys, or complete unlock links.
- Reserved `/_tunnel/` URLs belong to the relay authentication pages; never pass them to the local app. Reserve cookie names and drop malicious upstream attempts to set those relay cookie names.
- Sensitive control APIs bound to an internal Unix socket or loopback listener; never expose operator metrics/admin endpoints through the public wildcard route.
- No directory traversal through the tunnel protocol: agent never reads files as a result of a relay stream.
- Treat multi-tenant self-service hosting as abuse-sensitive: authenticated enrollment, bounded trials/quotas, abuse contact, suspend/revoke tooling, and threat reporting are prerequisites to opening it to strangers.

### 1.6 Explicit limitations

The tunnel cannot make an intentionally vulnerable local app safe, protect against a compromised relay, guarantee secrecy from the relay operator, or absorb unlimited DDoS attacks. Access to a protected tunnel permits whatever HTTP operations the upstream application exposes. Administrators should not expose services that assume any incoming request from localhost is fully trusted without understanding those privileges.

---

## 2. Required user experience and CLI

### 2.1 Primary command and startup result

```console
$ tunnel 3000
✓ Local HTTP service reachable: 127.0.0.1:3000
✓ Relay authenticated
✓ HTTPS endpoint active
✓ Visitor access: PROTECTED

Public URL:   https://bright-fox-7pc5m4x2b9qw6kjd.t.example.com
Share link:   https://bright-fox-7pc5m4x2b9qw6kjd.t.example.com/_tunnel/unlock#t=<redacted>

Forwarding HTTPS → 127.0.0.1:3000
Requests: 0 active | 0 total | Connected 00:00:04
Press Ctrl+C to close this ephemeral tunnel.
```

For a real CLI, the local secret is displayed only in a deliberate interactive output path, redacted in JSON status, process lists, diagnostic bundles, telemetry, and application logs. The agent should give a `--no-share-link` option for environments in which displaying a secret in the terminal is inappropriate. Avoid exposing secrets via command-line arguments, shell history, or environment variables when a credential file/stdin is available.

Do not claim `✓ HTTPS endpoint active` until the relay has confirmed a valid, already-provisioned wildcard certificate and an active route. The local HTTP health probe should be configurable because some applications require authentication or do not implement `/`.

### 2.2 CLI grammar

| Command | Required behavior |
|---|---|
| `tunnel 3000` | Open authenticated ephemeral HTTPS tunnel to loopback port |
| `tunnel 3000 --public` | Intentionally disable visitor auth; print warning |
| `tunnel 3000 --name demo` | Owner-locked persistent hostname (P1) |
| `tunnel 3000 --ttl 2h` | Close/expire the tunnel after TTL |
| `tunnel 3000 --upstream-host localhost:3000` | Override upstream Host for framework compatibility |
| `tunnel 3000 --json` | Machine-readable events, secrets omitted |
| `tunnel status [--json]` | Local tunnel status and lease state, no credentials |
| `tunnel access share [id]` | Generate another short-lived, single-redeem protected browser unlock link |
| `tunnel access rotate [id]` | Rotate access capability; revoke sessions |
| `tunnel access revoke [id]` | Immediately revoke visitor access |
| `tunnel doctor` | Check agent config, DNS, TLS, relay reachability, local service and clock |
| `tunnel login --relay https://relay.example.com` | One-time enrollment / account pairing |
| `tunnel logout` | Remove local enrollment; optionally revoke remote agent key |
| `tunnel relay init --domain example.com` | Self-hosted relay bootstrap (P1) |
| `tunnel relay doctor` | Check setup, wildcard DNS, ACME, ingress and certificates |
| `tunnel version` | Agent/relay build and supported protocol versions |

Exit status: `0` clean shutdown; `2` CLI/port validation; `3` local target unavailable; `4` enrollment/auth failure; `5` relay/DNS/TLS unavailable; `6` incompatible protocol; `7` quota/lease denial; `8` internal fault. On transient disconnect while running, the process remains active and tries reconnection, not an immediate exit.

### 2.3 Configuration precedence

Explicit CLI flags > environment variables for nonsecrets > user config file > compiled hosted defaults. Keep configuration optional and sparse. Show effective values in `doctor` with all secrets redacted.

Suggested user config: `~/.config/tunnel/config.toml` with `relay_url`, `agent_key_ref`, `default_access_mode=protected`, `default_ttl`, and optional output preferences. Secret keys reside in a separate 0600 file, or OS credential store if supported; no reliance on OS keychain for headless Linux machines.

### 2.4 UX and safety guardrails

- Human-readable errors with one exact remediation command; no stack traces by default.
- Never automatically fall back from protected to public mode, from verified TLS to plaintext, or from pinned loopback to a different address.
- Ctrl+C closes the tunnel, deregisters the lease, invalidates access, and exits quickly; SIGTERM does the same where possible.
- Auto reconnect uses exponential backoff with jitter; visible status changes to `RECONNECTING`, and public traffic gets 503 while unreachable.
- Default ephemeral hostname remains the same during transient reconnect and relay restart, provided lease/owner resume proof remains valid. A completely new invocation receives a new ephemeral name unless `--name` is used.
- A setup/login flow must clearly distinguish one-time operator provisioning from everyday zero-config client operation.

---

## 3. System architecture

```text
External browser / webhook / API client
          |
      HTTPS :443
          |
    Caddy (TLS, wildcard cert, HTTP redirect, edge limits)
          |
   Unix socket / 127.0.0.1 (trusted ingress only)
          |
   Go relay service
    - exact Host -> lease lookup
    - visitor authorization
    - quotas / routing / stream lifecycle
    - lease registry (SQLite)
          |
   authenticated long-lived WSS :443
          |
   yamux multiplexed session over binary WebSocket
          |
   Go local agent
    - fixed target: 127.0.0.1:3000
    - request/response adapter
    - reconnect / liveness / heartbeat
          |
   local HTTP / WebSocket application
```

**Components:** one `tunnel` Go executable with `agent`, `relay`, and `diagnostic` subcommands; Caddy is the only mandatory separate server process in the recommended production deployment. No Redis, PostgreSQL, Docker, Kubernetes, job queue, or third-party tunnel service in v1. SQLite owns the durable relay metadata and uses WAL mode with backup/restore procedures.

### 3.1 Why WSS + yamux

Outbound WSS works through ordinary TCP/443 egress policies and established TLS-capable corporate proxies better than assuming UDP. Coder’s `websocket` library supplies a byte-stream adapter (`NetConn`), and HashiCorp’s `yamux` supplies independent bidirectional streams and window-based flow control over that session. This avoids implementing a custom session-wide multiplexer from scratch. Validate the compatibility adapter under fragmentation, payload limits, half-close, cancellation, concurrent writes, reconnect, and DoS fuzzing; library use alone does not prove security. Disable permessage-deflate for the tunnel carrier by default because the stream payload may include secrets and compression complicates flow control and memory safety.

**Peer direction:** agent initiates the WSS session and acts as the yamux server, accepting streams; the relay acts as yamux client and opens a stream for each incoming public HTTP request/WebSocket upgrade. The WSS carrier remains alive independently of the number of proxied requests.

**Protocol versions:** `tunnel/1` with explicit server `min_version` and `max_version`; reject unsupported versions with a typed error. Allow additive feature negotiation but never accept unknown security-critical message fields by default.

### 3.2 Session handshake

1. Agent opens `wss://relay.example.com/v1/agent/connect`, with a verified TLS certificate, to the operator’s designated relay.
2. Relay sends protocol-version-supported set, a random nonce, its origin identity, and a short expiry.
3. Agent signs a domain-separated canonical handshake: `tunnel-agent-v1 || nonce || key-id || intended-relay-origin || version || timestamp || lease-intent`. The Ed25519 public key must already belong to an enrolled, non-revoked account.
4. Relay validates signature, nonce one-time use, clock bounds, owner/tenant quota, requested port lease, and optional named-host authorization; sends session ID, lease ID, fencing generation, and assigned hostname.
5. WSS switches to the yamux transport; optional control streams carry pings, GOAWAY, quota updates, lease revoke, and diagnostic events. Authentication always precedes multiplexed data.
6. Relay marks route ACTIVE only when both session and destination readiness are proven. Offline leases are not allocated to a different owner.

Do not rely on browser `Origin` for agent authentication. Reject browser-originating WSS handshakes at the agent-control endpoint and never accept cookie authentication for agents.

### 3.3 Stream application protocol

Avoid copying unparsed raw HTTP messages across trust boundaries. Use a deliberately small, versioned **length-prefixed typed framing** on each yamux stream (JSON metadata is acceptable for v1, with binary data frames). Hard cap metadata frames at 32 KiB and data chunks at 64 KiB; reject unknown mandatory types and oversized claims *before allocation*.

Per-direction frame order:

```
Request direction:  REQUEST_HEAD, REQUEST_DATA*, REQUEST_TRAILERS?, REQUEST_END
Response direction: RESPONSE_HEAD, RESPONSE_DATA*, RESPONSE_TRAILERS?, RESPONSE_END
Either direction:   ABORT(reason_code) / STREAM_CLOSE
Upgrade mode:       UPGRADE_ACCEPT then bidirectional UPGRADE_BYTES* until CLOSE
```

`REQUEST_HEAD` includes: request ID, lease ID, fencing generation, method, normalized scheme (`https`), path + raw query, strictly validated headers, body-length-known flag, optional announced content length, and streaming/upgrade feature flags. The relay supplies an authenticated, verified remote-IP field and public origin separately from untrusted visitor headers. `RESPONSE_HEAD` includes status, application headers, content-length mode and upgrade accept metadata. All frames are associated with exactly one stream and one owning lease/session generation. Neither agent nor visitor may mutate its authenticated destination after lease creation.

**Flow control:** yamux per-stream window controls transport bytes; application writes block on full windows. Do not create an unbounded `io.ReadAll`, request queue, or goroutine per body chunk. Per stream use a fixed-size buffer and a bounded number of goroutines. The relay reads and authorizes request headers before allocating stream state. Response streaming is pipelined while request uploads are still in progress, including early-error responses. On HTTP client cancellation, propagate a stream abort to the agent and cancel the local transport. Partial streamed responses cannot be retried or replaced with a new status code.

**Header correctness:** relay strips hop-by-hop connection headers, forwarding spoofed headers, relay credentials, and ambiguous lengths; uses explicit proxy metadata. Preserve app-critical `Host`, `Accept-Encoding`, cookies, WebSocket handshake fields (where permitted), redirects, and binary bodies. Support `100 Continue`/`103 Early Hints` and trailers only if implemented with correct semantics and automated interoperability coverage; otherwise explicitly return a deterministic unsupported-protocol result rather than silent corruption. Streaming SSE must flush incrementally, not coalesce until response closure. Compression passthrough should not inflate compressed app data in the relay.

**WebSocket upgrades:** public request goes through full visitor authentication and route authorization; agent performs a matching local HTTP/1.1 Upgrade to `127.0.0.1:PORT`. Only after upstream returns a valid `101` and matching `Sec-WebSocket-Accept` does relay finalize public upgrade. Thereafter pass byte streams both directions, observing cancellation, max connection life, idle timers, quotas, and backpressure. No WebSocket payload parsing or rewriting needed in the tunnel data plane. Do not accept arbitrary upgrade protocol tokens.

### 3.4 Ownership state machine

Lease statuses: `PROVISIONING → ACTIVE → RECONNECTING → ACTIVE`, `ACTIVE → DRAINING → CLOSED`, `ACTIVE/RECONNECTING → EXPIRED`, `ANY → REVOKED`. Maintain a monotonically increasing session generation (fencing epoch); each reconnect atomically supersedes the prior generation. Old session streams cannot route new requests and are closed after a short drain. A new tenant cannot claim a terminated anonymous hostname; random names are never reused by policy. Named host ownership is durable and tenant-bound.

Keep a short reconnect grace (e.g., 90 seconds) before expiring an ephemeral lease after disconnection, with no unauthorized forwarding while offline. Relay restart must load owner and token verifier records from SQLite and allow the same agent key to resume a still-valid lease; the public URL should not change on that resume.

---

## 4. DNS, TLS and one-time relay deployment

### 4.1 DNS (one time)

For `example.com` and the namespace `t.example.com`:

```
relay.example.com     A     <VPS IPv4>
*.t.example.com       A     <VPS IPv4>
```

Add matching AAAA records only when the VPS actually serves IPv6. Avoid publishing nonfunctional AAAA records. No per-tunnel DNS writes are needed. The wildcard matches exactly one subdomain label. Implement exact one-label hostname verification (`<id>.t.example.com`) in the relay.

### 4.2 TLS

Use Caddy for HTTPS on `relay.example.com` and `*.t.example.com`, with ACME renewal and HTTP-to-HTTPS redirect. **Wildcard certificates require DNS-01**, which needs provider API integration or delegated validation. Scope DNS API credentials to the necessary ACME challenge zone; do not put an unrestricted DNS provider API token in agent builds. Pre-provision and verify the wildcard certificate before the first public tunnel; do not wait for each client hostname to receive an individual certificate. Store ACME state and private keys with strict permissions and durable backed-up storage. The relay process itself binds only to loopback or a Unix socket behind Caddy.

Example **conceptual** Caddy configuration (provider-specific build and credential configuration still required):

```caddyfile
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}

*.t.example.com {
    tls {
        dns <supported-dns-provider> {env.DNS_API_TOKEN}
    }
    reverse_proxy 127.0.0.1:8080
}
```

Production config must add trusted-proxy header sanitization, request limits, separate admin binding, managed secrets, structured logging, health checks, and tested WS streaming/reload behavior. Caddy wildcard routing is not a substitute for lease authorization in the Go relay. For a custom domain feature later, Caddy on-demand TLS must be protected by an explicit authorization/ownership `ask` endpoint, not blanket unbounded issuance.

### 4.3 Provisioning UX

`sudo tunnel relay init --domain example.com --dns-provider <name>` should:

1. Check prerequisites and privileges, VPS egress, public listening ports TCP/443 and (for HTTP redirect/other challenges) TCP/80.
2. Generate a secure relay config, persistent encryption/signing secrets, and initial owner enrollment token (printed once).
3. Install a locked-down systemd unit and Caddy config; drop runtime privileges after privileged setup.
4. Print the two exact DNS records and proof-of-ownership instructions; **cannot silently configure arbitrary DNS providers without supported API credentials**.
5. Complete ACME DNS-01 and verify wildcard TLS externally.
6. Check service health and isolated agent enrollment.
7. Return a reproducible operator report and a one-time `tunnel login --relay ...` bootstrap command.

Bootstrap should be idempotent and able to resume safely after failure. Never overwrite existing keys or valid certificates blindly. Do not make systemd restart loops appear to be successful provisionings.

### 4.4 Operator hardening

Dedicated unprivileged service account; `NoNewPrivileges`, `ProtectSystem=strict` or equivalent with explicit writable data directory, restricted syscalls/capabilities and bounded file descriptors. Only Caddy listens publicly; firewall deny other inbound ports; operator admin APIs on a Unix socket. SQLite and certificates backed up encrypted with tested restoration. Apply regular Go/Caddy/dependency security updates. Prefer signed release binaries, SHA-256 checksums, SBOM, dependency scanning and reproducible provenance where feasible. No user telemetry by default; opt-in diagnostics only.

---

## 5. Stateful data, isolation and authorization

Suggested SQLite tables:

- `tenants(id, status, created_at, quotas_json)`
- `agent_keys(id, tenant_id, ed25519_public, status, created_at, revoked_at)`
- `leases(id, tenant_id, agent_key_id, hostname, local_port, access_mode, generation, status, expires_at, reconnect_until, created_at)`
- `access_tokens(id, lease_id, verifier, scope, created_at, expires_at, revoked_at, max_uses, uses)`
- `visitor_sessions(id, lease_id, token_generation, session_verifier, created_at, idle_expires_at, absolute_expires_at, revoked_at)`
- `enrollment_codes(id, verifier, tenant_id, expires_at, used_at, issued_by)`
- `audit_events(id, time, actor, tenant_id, lease_id, category, result, metadata_redacted)`

Index hostname unique, active lease foreign keys, owner IDs and token verifier lookup keys; enforce FK constraints and transactional updates. Use a **single authoritative lease owner**. Every request uses an immutable authorization snapshot plus live generation check before opening a stream. No tenant can renew or revoke a different tenant’s lease. Database migrations must be versioned and rollback/backup tested. Secrets must not appear in SQLite debug dumps or generic error strings.

For v1 the active WSS connections exist only in relay memory; SQLite stores restart-safe identity/lease authorization, not serializable socket pointers. Single relay instance is the supported topology. Multi-node requires shared control-plane state, session-affinity/routing and fencing redesign; do not assert active-active HA until implemented.

---

## 6. Limits, quotas, timeouts and reliability

**Initial defaults to tune by empirical load testing (not performance promises):**

| Limit | Initial default | Behavior |
|---|---:|---|
| Request header bytes | 32 KiB | Reject oversized/ambiguous headers with 431/400 |
| Maximum buffered body | 64 KiB per stream direction | Streaming backpressure, never full buffering |
| HTTP request body | 64 MiB | 413, adjustable up to operator cap |
| HTTP concurrent streams per lease | 64 | 503 or bounded short queue; no unbounded queues |
| WebSockets per lease | 32 | 429/503 prior to upgrade |
| Agent sessions per agent key | 1 active for a given lease | Fenced generations prevent takeover/races |
| Local connect timeout | 3 s | 502/504 |
| Incoming header timeout | 10 s | 408 |
| Initial upstream response timeout | 30 s default, configurable | 504 if no response headers yet |
| Tunnel ping cadence | 15 s | Heartbeat check |
| Dead-session detection | 45 s | Mark RECONNECTING, stop new streams |
| Reconnect grace | 90 s | Resume owner-bound lease, else expire |
| Reconnect backoff | 250 ms to 30 s plus jitter | Stable under relay restart |
| Browser visitor session | 1 h idle / 12 h absolute | Server-enforced expiration |
| Share-link token | 15 min, default single redeem | Revocable independent of tunnel lifetime |
| Ephemeral lease lifetime | While agent runs + reconnect grace | Non-recyclable hostname |
| Access logs | Redacted metadata only | Configurable short retention |

Do not impose a universal 30-second deadline on long-running SSE responses or WebSockets. Enforce separate first-byte and *idle-progress* timers and explicit maximum lifetime for WS connections. End-to-end budget must account for slow mobile visitors and external webhooks. Support `Expect: 100-continue` only with correct semantics. Define behavior for multiple concurrent `tunnel 3000` processes as independent leases; no accidental shared global agent session.

### Status-code semantics

- `400/421`: malformed request or public Host/SNI mismatch.
- `401/403`: no valid visitor credential / authenticated but forbidden.
- `404`: hostname unregistered or expired (no cross-tenant route hint).
- `408/413/431/429`: timeout, size, header, rate quota respectively.
- `502`: agent reached but local upstream dial/proxy failed, or invalid backend response.
- `503`: relay online but matching agent offline, lease draining, or capacity unavailable (bounded `Retry-After` when appropriate).
- `504`: an upstream response deadline was exceeded before headers.
- If the HTTP response has already started, a subsequent disconnect closes the stream; do not claim to return a new 502/504 once headers are committed.

**Retry semantics:** Never automatically replay a request that may have reached the local application, regardless of HTTP method. A lost response from a processed POST must remain ambiguous to the caller; retries require caller-level idempotency keys or explicit application policy. Reconnecting affects new requests only, and old generations are fenced.

---

## 7. Observability and operational controls

### Health endpoints (internal only)

- `/health/live`: Go process scheduler and server loop alive.
- `/health/ready`: SQLite writable, route registry initialized, expected proxy trust configuration valid, public TLS ready (checked by operator probe), and capacity to accept a tunnel session.
- `/metrics`: Prometheus metrics, internal network only.

### Metrics, always bounded cardinality

- `tunnel_active_leases`, `tunnel_active_sessions`, `tunnel_reconnecting_leases`
- `tunnel_http_requests_total{outcome,access_mode}`, `tunnel_http_inflight`
- `tunnel_visitor_auth_failures_total{reason}`
- `tunnel_upstream_dial_seconds`, `tunnel_request_total_seconds`
- `tunnel_stream_bytes_total{direction}`, `tunnel_backpressure_seconds_total`
- `tunnel_ws_active`, `tunnel_ws_close_total{reason}`
- `tunnel_session_reconnect_total{cause}`, `tunnel_lease_fencing_rejections_total`
- `tunnel_capacity_rejections_total{reason}`, `tunnel_tls_cert_expiry_seconds`

Do not use raw hostname, URL, token, IP, or user identifier as unbounded public metric labels. Logs should have a correlation ID per request, a short opaque lease reference, a latency breakdown (TLS/edge ingress, auth, stream-open, upstream dial, upstream time-to-first-byte, body transfer), and a typed fault classification. Never log the full path/query by default; these often contain tokens/PII. Default logs exclude application payloads and full share links. Event clocks use monotonic timing for durations and UTC for metadata.

### `tunnel doctor` evidence

Report enrollment key permissions, selected relay address, current TLS identity validity, DNS wildcard resolution, Caddy WS path accessibility, time skew, target loopback listener, upstream HTTP probe, lease authorization, and any local proxy interference. Report verified facts separately from inferred/unknown facts.

---

## 8. File layout and module ownership

```text
instant-tunnel/
  cmd/tunnel/main.go               # argv + command dispatch only
  internal/cli/                    # terminal UX, flags, diagnostics
  internal/config/                 # sparse schema, validation, redaction
  internal/identity/               # enrollment, keypair, signature, revoke
  internal/access/                 # visitor sessions, token verifier, CSRF
  internal/agent/                  # lifecycle, reconnection, local upstream
  internal/relay/                  # lease/service lifecycle, ingress dispatch
  internal/lease/                  # lease state machine + fencing
  internal/transport/              # WSS + yamux glue, bounded streams
  internal/protocol/               # versioned frame schema and parsers
  internal/proxy/                  # HTTP/WS/SSE proxy adapters
  internal/limits/                 # budgets, limits, fairness, rate limiting
  internal/store/sqlite/           # migrations and transactional lease storage
  internal/metrics/                # redacted logs and metrics
  internal/server/                 # internal health and admin interface
  packaging/systemd/
  packaging/caddy/
  packaging/install/
  tests/integration/
  tests/security/
  tests/chaos/
  tests/load/
  docs/SECURITY.md
  docs/DEPLOY.md
  docs/PROTOCOL.md
  docs/OPERATIONS.md
  docs/THREAT_MODEL.md
  docs/COMPATIBILITY.md
```

**Avoid a monolithic relay manager.** `identity` authenticates the agent; `lease` owns hostname and generation; `access` authorizes visitors; `transport` carries opaque bounded streams; `proxy` translates HTTP/WS semantics; `limits` independently authorizes resource allocation; `store` persists metadata. Define interfaces once and never create a second routing or credential authority in CLI/server handlers.

### Selected dependencies

- Go standard `crypto/ed25519`, `crypto/rand`, `crypto/tls`, `net/http`, `net`, `context`.
- `github.com/coder/websocket` for WSS carrier and net.Conn bridge.
- `github.com/hashicorp/yamux` for multiplexing, flow control and half-close semantics.
- Caddy for TLS and edge reverse proxy.
- Mature maintained SQLite Go driver chosen after maintenance/CVE review (driver selection is a build-time decision).
- Structured logging via standard Go `log/slog`; metrics dependency as appropriate.

Pin exact released versions during implementation and run vulnerability/license scans. Do not invent transport encryption on top of trusted, authenticated WSS unless a distinct security requirement justifies it.

---

## 9. Acceptance test plan (must run, not merely write)

### 9.1 Functional invariants

1. `tunnel 3000` registers a protected public HTTPS hostname and proxies expected status/headers/body of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS`.
2. Default unauthenticated visitor cannot cause **any** upstream connection, measured at the local service.
3. `--public` is the only path to anonymous visitor routing; no TLS/auth downgrade occurs during fallback or reconnect.
4. Concurrent requests and uploads do not cross-wire bytes, request IDs, response order, or tenant identities.
5. WebSocket handshake and echo across the public URL work in both directions while HTTP traffic remains responsive.
6. SSE bytes arrive incrementally, not only after server close.
7. HTTP response cookies, redirects, binary bodies and app authorization round-trip correctly without leaking tunnel credentials.
8. DNS and wildcard certificate are valid from an actual external network and a fresh TLS client, not only VPS localhost.
9. Unregistered Host never routes to any agent; Host/SNI mismatch fails closed.
10. Client SIGINT and relay stop leave no dangling ACTIVE lease, and the next start behaves predictably.

### 9.2 Adversarial security matrix

- Wrong tenant cannot claim, renew, rotate, stream, revoke, or read another tenant’s lease.
- Stolen/randomized/expired enrollment code denied; revoked Ed25519 identity denied; valid signed replay denied; old session generation denied after reconnect.
- Guessing hostname alone denied; visitor token missing, malformed, rotated, expired, re-used beyond max-use, or revoked denied before local dial.
- Browser cookie-authenticated WebSocket or unsafe HTTP method with hostile, `null` or omitted Origin denied unless a separately verified CSRF proof exists; same-site cross-tenant subdomain CSRF attempt denied; malicious CSRF attempt against unlock/logout/revoke denied.
- Tunnel access tokens in the dedicated authentication header, URI query, URI fragment, cookies and logs checked for accidental propagation to application, Caddy logs, relay logs, metrics and diagnostic dumps.
- Public `Host` forged as localhost, wrong tenant, alternate suffix, nested subdomain, IDN confusable, trailing dot or embedded port denied as appropriate.
- HTTP request smuggling fuzz suite: TE+CL, duplicate CL, invalid chunk frames, hop-by-hop header spoof, percent-encoded path ambiguity, trailers, malformed header names.
- Oversized metadata/frame, million idle streams, stalled socket read/write, partial WebSocket frame, memory pressure, deliberate disconnect during body upload, header/body slowloris tests must remain resource-bounded.
- An unauthenticated remote request cannot persuade the agent to fetch RFC1918 addresses, cloud metadata, arbitrary localhost ports, HTTP proxies, Unix sockets, or filesystem content.
- Insecure TLS, expired cert, wrong hostname, compromised/missing key, unsupported protocol and invalid server origin all fail closed.
- Controlled fault injection proves that a broken request never silently upgrades from private to public.

### 9.3 Chaos and recovery

- Kill the agent, kill relay, reboot relay, reload Caddy, cut network between agent and VPS, DNS temporarily unavailable, SQLite locked/corrupt, crash during lease creation/revocation, and sudden SIGKILL.
- Verify bounded reconnect backoff and no infinite spin; hostname remains owner-locked while offline.
- Reconnect at generation N+1 invalidates generation N; parallel old/new sessions cannot both accept traffic.
- Kill connections during non-idempotent POST; verify no automatic duplicate POST or deceptive success response.
- Restore backed-up SQLite and ACME data to clean VPS; prove operator recovery and ensure old revoked identities remain revoked.
- Service restarts restore public availability once the same agent reconnects without requiring a new client port-forward configuration.

### 9.4 Performance and release baseline

Benchmarks must define VPS region, CPU/RAM, public-client region, payload sizes, service latency, TLS warm/cold state and number of endpoints. Targets are engineering gates, not guaranteed global latency:

- Single small VPS target: at least 100 concurrent live HTTP connections across several agent leases without OOM or sustained starvation.
- Per-lease default: 64 HTTP and 32 WebSockets behave predictably, with rejection beyond quotas rather than unbounded growth.
- Mix 1 KiB, 1 MiB and 64 MiB bodies; verify peak memory is bounded by stream count and configured buffers, not body size.
- No unexpected request loss/corruption at 1,000+ completed requests under a concurrent functional soak; no cross-tenant isolation defect.
- Record p50/p95/p99 additional latency versus direct service (where comparable); tune rather than assert an unmeasured SLA.
- Long-run soak at least 24 hours, including multiple disconnect/reconnect cycles, with resource and goroutine counts stable after quiescence.
- Fuzz protocol decoders and public HTTP adapters; run Go `-race` integration tests and dependency/CVE scans.

A successful CI suite is necessary but insufficient: perform a live public HTTPS external-client test for each release candidate.

---

## 10. Build phases and definition of done

### Phase 0 — Wire and security foundations

- Create Go project, immutable config schema, explicit error taxonomy, strict parser, Ed25519 keypair support, enrollment flow, SQLite schema, threat model.
- Create stable command UX (`tunnel 3000`) and `doctor` stubs that report unsupported states honestly.
- Fuzz framing, validate identity replay protections, test host binding and session fencing.

**Exit gate:** identity and lease security tests pass; no network forwarding feature is claimed.

### Phase 1 — Functional private tunnel

- Caddy wildcard TLS, self-hosted bootstrap, authenticated WSS, yamux streams, exact loopback target, HTTP request/response streaming, private access token/cookie, bounded concurrency and reconnect.
- HTTP methods, upload and SSE tested over actual public HTTPS.

**Exit gate:** the primary command yields an authenticated URL that works from a separate network, and unauthenticated requests never reach loopback.

### Phase 2 — WebSockets and operational stability

- Correct 101 handshake, bidirectional WS byte forwarding, timeouts/half-close, cancellation, quotas, recovery across agent/relay/Caddy restart, metrics, log redaction, signed releases, backup restore.
- Security and chaos suites and external client tests pass.

**Exit gate:** deployable single-node production v1.0 with explicit availability limitations.

### Phase 3 — Convenience without compromising boundaries

- Persistent owner-locked named subdomains, `tunnel access rotate/revoke`, installer/bootstrap polishing, zero-interaction diagnostic output, multi-platform packaging and automated updates with signature verification.

**Exit gate:** repeated everyday use remains `tunnel 3000`; setup never compromises protective defaults.

### Later, only on demonstrated need

Custom domains with proof-of-ownership/on-demand TLS authorization, multi-service agent sessions, optional private ACLs/OIDC, active-active edge architecture with shared lease authority, HTTP/3/QUIC carrier, TCP tunneling with separate security policy, full zero-knowledge TLS-pass-through mode with documented tradeoffs.

---

## 11. Production release checklist

- [ ] Public wildcard cert issued via DNS-01, auto-renewal observed and expiry monitoring installed.
- [ ] Actual separate-network browser/curl/webhook connectivity confirmed.
- [ ] No inbound port opened on the agent host.
- [ ] Agent identity enrollment/revocation and stale-session fencing tested.
- [ ] Protected is default; no visitor request reaches localhost before authorization.
- [ ] Domain host routing is tenant-safe with exact allowlists and no default fallback.
- [ ] WebSockets/SSE/large uploads and concurrent requests pass live testing.
- [ ] No secret leakage in logs, Caddy, metrics, crash reports, JSON output or local app.
- [ ] Backpressure, size limits, quota denials and fair scheduling tested under load.
- [ ] Shutdown/reconnect/restart/partial-response semantics are documented and tested.
- [ ] TLS validation, passwordless signed agent auth and visitor session lifecycle are reviewed.
- [ ] Dependency/CVE scans, race tests, parser fuzzing and adversarial tests pass.
- [ ] SQLite/ACME encrypted backup and restore have been exercised.
- [ ] Signed binary provenance, least-privilege systemd, dedicated service user and firewall restrictions verified.
- [ ] Operator incident path for key revocation, tunnel takedown, DDoS/abuse and rollback documented.
- [ ] Product clearly discloses that relay can inspect traffic; no E2EE claim.
- [ ] Performance and reliability claims match measured environment and published limitations.

---

## 12. Design rationale and authoritative references

- Let’s Encrypt, **Challenge Types**: DNS-01 required for wildcard certificate issuance. https://letsencrypt.org/docs/challenge-types/
- Caddy, **Automatic HTTPS** and **TLS**: managed certificates, DNS challenge, wildcard behavior and on-demand restrictions. https://caddyserver.com/docs/automatic-https and https://caddyserver.com/docs/caddyfile/directives/tls
- Go, **httputil ReverseProxy**: forwarding header rewriting and spoofing/ambiguity pitfalls. https://pkg.go.dev/net/http/httputil
- OWASP, **Session Management Cheat Sheet**: avoid bearer session tokens in URLs and protect cookie attributes. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP, **WebSocket Security Cheat Sheet**: validate Origin, authorize upgrades, bound messages and connections. https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
- Coder, **websocket**: idiomatic WebSocket with `net.Conn` adapter; adapter-specific read-limit semantics require careful test coverage. https://github.com/coder/websocket and https://pkg.go.dev/github.com/coder/websocket
- HashiCorp, **yamux**: multiplexed streams, window-based flow control, and FIN/RST semantics. https://github.com/hashicorp/yamux
- ngrok, **Security**: useful disclosure precedent that edge TLS termination allows relay inspection. https://ngrok.com/security

## 13. Final architectural invariant

> Only a validly enrolled agent may attach its explicitly configured loopback port to an owner-bound hostname; only an authorized visitor (unless the owner deliberately chose public mode) may cause a request to be forwarded; every forwarded stream is isolated, bounded, cancellable, attributable to exactly one valid lease generation, and encrypted across public networks. Failure is observable and never silently weakens these rules.
