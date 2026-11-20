# Instant Tunnel — Anti-Spec v1.0

**Product:** Instant Tunnel  
**Purpose:** Define what the product must NOT become, implement, depend upon, or require from its users.

## 1. Product identity — What we are NOT building

- AS-001: NOT another ngrok-sized platform with dozens of unrelated capabilities.
- AS-002: NOT a general-purpose reverse-proxy management system.
- AS-003: NOT a VPN, mesh network, overlay network, or Tailscale replacement.
- AS-004: NOT a remote desktop, SSH access, or remote administration tool.
- AS-005: NOT an API gateway with application-level business logic.
- AS-006: NOT a service mesh or microservices orchestration platform.
- AS-007: NOT a cloud hosting provider, PaaS, or application deployment system.
- AS-008: NOT an agent orchestration, AI routing, or automation platform.
- AS-009: NOT an identity-management platform or centralized enterprise SSO system.
- AS-010: NOT a generic TCP/UDP forwarding framework in v1.

**Boundary:** Expose a selected local HTTP service through a secure public HTTPS endpoint. Nothing more.

## 2. User experience — What users must NOT experience

- AS-011: No required DNS configuration for each tunnel.
- AS-012: No user-managed certificate generation or renewal.
- AS-013: No router configuration, port forwarding, or inbound firewall changes on the client.
- AS-014: No YAML configuration required for ordinary usage.
- AS-015: No mandatory web dashboard.
- AS-016: No registration workflow for every new tunnel.
- AS-017: No repeated login ceremony while valid enrollment credentials exist.
- AS-018: No dependency on Docker, Kubernetes, Node.js, or Python on client machines.
- AS-019: No requirement to learn networking terminology before using the tool.
- AS-020: No interactive wizard for basic `tunnel PORT` execution.
- AS-021: No manual hostname provisioning for ephemeral tunnels.
- AS-022: No silent modification of the user's existing applications, network settings, or firewall.
- AS-023: No confusing failures such as showing "Connected" when external routing is unavailable.
- AS-024: No unnecessary persistent background service on client machines.
- AS-025: No compulsory configuration files when secure defaults suffice.

**Boundary:** After initial enrollment, ordinary hosting must require only `tunnel PORT`.

## 3. Architecture — What we refuse to introduce

- AS-026: No microservices architecture for the initial relay.
- AS-027: No Kubernetes requirement.
- AS-028: No Redis, Kafka, RabbitMQ, etcd, or distributed coordination infrastructure in v1.
- AS-029: No mandatory PostgreSQL cluster.
- AS-030: No requirement for multiple public relay servers.
- AS-031: No custom cryptographic algorithms.
- AS-032: No homegrown TLS implementation.
- AS-033: No unnecessarily invented multiplexing protocol when established libraries meet requirements.
- AS-034: No dynamic plugin system for transport implementations.
- AS-035: No abstraction layer for hypothetical future networking backends.
- AS-036: No generic workflow engine.
- AS-037: No internal policy language or rules DSL.
- AS-038: No event-sourcing architecture for routine lease lifecycle state.
- AS-039: No multiple authoritative sources for lease ownership.
- AS-040: No interchangeable storage engines until there is an actual requirement.
- AS-041: No singleton god object controlling authentication, routing, streams, persistence, and CLI behavior.
- AS-042: No duplicated routing, authorization, or lifecycle implementations.
- AS-043: No extension infrastructure without a concrete supported use case.

**Boundary:** A compact Go relay, a compact Go client, a TLS edge, and minimal durable state. Separation of responsibilities without unnecessary distributed infrastructure.

## 4. Security — What must NEVER be considered acceptable

- AS-044: No anonymous public exposure by default.
- AS-045: No disabling TLS verification to fix connectivity problems.
- AS-046: No hardcoded production secrets or shared default credentials.
- AS-047: No permission escalation through reconnect, fallback, or recovery.
- AS-048: No unrestricted proxy access into the client's local network.
- AS-049: No ability for visitors to choose the upstream IP address or port.
- AS-050: No relay-side execution of arbitrary user-provided commands.
- AS-051: No unauthenticated administrative endpoints.
- AS-052: No logging of private access tokens, credentials, or application bodies by default.
- AS-053: No cross-tenant request forwarding or lease takeover.
- AS-054: No insecure compatibility mode quietly activated on failure.
- AS-055: No assumption that a public HTTPS URL automatically means the exposed application is safe.
- AS-056: No advertising end-to-end confidentiality against the relay operator when TLS terminates at the relay.
- AS-057: No security feature that only exists in configuration but is not enforced on the live request path.
- AS-058: No unbounded request buffering, queues, or connection counts.
- AS-059: No silently continuing protected traffic when authorization state cannot be validated.
- AS-111: No remote selection, launch, or parameterization of local processes. A future local stdio adapter executes only operator-specified commands; visitor input never chooses executables, arguments, working directories, or environment.
- AS-112: No generic OAuth/app-token passthrough as tunnel authentication. Application tokens never substitute for relay credentials and relay credentials never become application auth; audience/scope validation happens at the application boundary on the exact token the client sent.
- AS-113: No obsolete-session-model requirement. The stateless 2026-07-28 transport must work without a protocol-level session id; legacy session ids pass through opaquely where present, never as a universal gate.
- AS-114: No silent public exposure for MCP (or any) clients that cannot present visitor credentials. An unsupported client auth configuration fails closed; it never flips a protected lease to public.

**Boundary:** Security must be intrinsic to the forwarding path, not supplied by a large security administration platform.

## 5. Networking — What we don't want

- AS-060: No dependence on UPnP or automatic router changes.
- AS-061: No peer-to-peer NAT traversal requirement.
- AS-062: No STUN/TURN/ICE subsystem.
- AS-063: No per-tunnel certificate issuance.
- AS-064: No per-tunnel DNS changes.
- AS-065: No polling-based HTTP forwarding when persistent connections are available.
- AS-066: No global serialized request queue.
- AS-067: No design where a slow upload unnecessarily blocks unrelated logical streams.
- AS-068: No arbitrary full-body buffering before forwarding.
- AS-069: No uncontrolled automatic retry of non-idempotent requests.
- AS-070: No redirect-following engine within the tunnel.
- AS-071: No generic HTTP content rewriting, HTML injection, or response transformation.
- AS-072: No reliance on application-specific protocols or frameworks.

**Boundary:** Forward supported HTTP traffic faithfully; do not become an application middleware platform.

## 6. Reliability — What we don't want to mistake for production quality

- AS-073: No pretending reconnection guarantees uninterrupted requests.
- AS-074: No indefinite retry of permanently invalid credentials.
- AS-075: No infinite reconnect loops without backoff.
- AS-076: No stale session taking authority from a newer session.
- AS-077: No returning successful HTTP responses for requests whose delivery is uncertain.
- AS-078: No hidden fallback to another tenant, port, or local application.
- AS-079: No relying exclusively on successful unit tests for production qualification.
- AS-080: No claiming high availability on a single VPS.
- AS-081: No treating a listening socket as proof that the complete tunnel is operational.
- AS-082: No memory growth proportional to unlimited request sizes.
- AS-083: No permanently orphaned leases after process crashes.
- AS-084: No destructive automatic state recovery that discards ownership or revocation evidence.
- AS-085: No persistence of dead connection state as though it were an active socket.

**Boundary:** Honest failures and deterministic recovery are more important than an appearance of continuous availability.

## 7. Deployment and operational complexity

- AS-086: No dependency on proprietary cloud infrastructure.
- AS-087: No mandatory external control-plane service.
- AS-088: No requirement to run a database cluster.
- AS-089: No mandatory telemetry export to a third-party vendor.
- AS-090: No managed billing, subscriptions, or payment-processing subsystem.
- AS-091: No hosted user-account marketplace.
- AS-092: No enterprise organization hierarchy, team administration, or RBAC framework in v1.
- AS-093: No browser-based configuration console required to operate the relay.
- AS-094: No elaborate observability stack necessary for a small deployment.
- AS-095: No automatic updates that unexpectedly replace running executables.
- AS-096: No background downloads of unverified executables.
- AS-097: No mandatory vendor account for a self-hosted relay.
- AS-098: No reliance on a particular DNS provider once initial DNS/TLS prerequisites are satisfied.

**Boundary:** Operators can deploy and maintain a relay using familiar system tools. A public server and domain are legitimate infrastructure requirements, not features we should pretend to eliminate.

## 8. Features explicitly deferred beyond v1

These are not permanently forbidden, but they cannot block the first production release.

| Feature | Decision |
|---|---|
| Custom domains | Defer |
| Generic TCP forwarding | Defer |
| UDP forwarding | Defer |
| Multiple local ports under one lease | Defer |
| Geographic relay selection | Defer |
| Multi-region deployment | Defer |
| Relay clustering | Defer |
| Multi-user organization administration | Defer |
| Public management API | Defer |
| Web dashboard | Exclude unless later justified |
| Analytics dashboard | Exclude unless later justified |
| Traffic recording and replay | Exclude unless later justified |
| Request inspection/debugging proxy | Separate product concern |
| Plugin ecosystem | Exclude |
| User-written forwarding scripts | Exclude |
| Application deployment or process management | Exclude |
| stdio-to-HTTP MCP adapter (`ocliv mcp expose`) | Defer to V1.1; when built, operator-selected commands only, loopback-only, lifecycle-bound, resource-bounded (M07/M08) |
| Local stdio management MCP | Defer to V1.1; narrowly scoped, local, opt-in only (M12) |
| Built-in OAuth identity provider | Exclude; upstream MCP servers enforce OAuth, Ocliv forwards `Authorization` opaquely (M04) |

Persistent named subdomains, secure share-link management, automatic relay provisioning, and basic diagnostics remain legitimate planned capabilities; they must not be expanded into a general management platform.

## 9. Engineering anti-patterns

- AS-099: Do not create interfaces merely to wrap single concrete implementations.
- AS-100: Do not add configuration options for choices that have one sensible supported default.
- AS-101: Do not duplicate validation logic between CLI entry points.
- AS-102: Do not mix the data plane and administrative authority in one unstructured request handler.
- AS-103: Do not disguise fatal errors as warnings.
- AS-104: Do not mark features complete because mocked paths work.
- AS-105: Do not introduce a dependency whose operational cost exceeds the functionality it supplies.
- AS-106: Do not optimize hypothetical distributed scaling before measuring the single-relay bottlenecks.
- AS-107: Do not build abstractions for future versions before the current behavior is correct.
- AS-108: Do not add complexity to compensate for unclear or poorly defined behavior.
- AS-109: Do not confuse code modularity with the need for independently deployed services.
- AS-110: Do not implement features without a concrete user-facing requirement, explicit responsibility, and acceptance test.

## 10. Scope enforcement

Any proposed implementation or feature must answer:

1. Does it directly improve instant hosting, security, reliability, or essential maintainability?
2. Does it remove a real user or operator burden?
3. Can it be implemented without introducing disproportionate dependencies or infrastructure?
4. Does it preserve the one-command experience?
5. Is it required for production correctness, or simply attractive to implement?
6. Would removing it prevent the tunnel from fulfilling its defined purpose?

**Rejection rule:** If a feature does not materially contribute to the product's core purpose, and does not satisfy a necessary security, reliability, or operational requirement, it is excluded.

**Exception rule:** An exclusion may be revised only through a documented scope change stating the concrete need, alternatives, additional complexity, and acceptance criteria. Security prohibitions are not waived by ordinary scope changes.

---

## Final product boundary

The product should do four things exceptionally well:

1. Connect a local HTTP service to a public HTTPS endpoint.
2. Control who may access it.
3. Forward concurrent HTTP and WebSocket traffic correctly.
4. Recover predictably from disconnections and failures.

**Everything else must justify its existence.**

The goal is not to build the most feature-rich tunneling platform.

The goal is to build the smallest system that makes secure, reliable, instant hosting genuinely effortless.
