# Shared Ocliv relay — readiness plan (BLOCKED: no operated relay)

The ordinary client flow (`ocliv login` once, then `ocliv 3000` /
`ocliv mcp 3000`) only becomes genuinely simple when a shared relay
already exists. Self-hosting (dynv6 + Caddy + public IP) stays the
advanced path for operators who want full ownership.

No code in this repository provisions, deploys, or operates that shared
relay. This document records exactly what operating one requires, what
the client contract is, and what stays blocked until an operator acts.

## Operating requirements

1. **Public ingress**: one host with a stable public IPv4 (or IPv6)
   address, TCP 80 + 443 reachable. No CGNAT, no NAT without port
   forwarding.
2. **DNS**: a registered domain with an A/AAAA record for the relay
   host and a wildcard record (`*.t.<domain>`) for tunnel endpoints.
   MCP path routes (`/r/<id>/mcp`) need only the single host record.
3. **TLS**: ACME via the existing single-host Caddy template; wildcard
   issuance via DNS-01 for generic `ocliv PORT` tunnels.
4. **Relay process**: `ocliv relay serve --listen=127.0.0.1:8080
   --data=/var/lib/ocliv --domain=<domain>` behind Caddy, systemd
   unit from `packaging/systemd/`, backups per `docs/OPERATOR.md`.
5. **Enrollment**: operator issues one-time codes (`relay issue-enroll`);
   codes travel out-of-band, never in logs.
6. **Capacity policy**: per-tenant quotas already exist in
   `internal/limits`; the operator must set and monitor them, plus
   abuse revocation (`access revoke`) and key rotation.
7. **Recovery**: restore procedure must never resurrect revoked
   authority (tested in `internal/relay/relay_backup_test.go`);
   operator keeps off-host backups.

## Minimum client onboarding contract

- Client installs one binary; no Go, Caddy, systemd, Docker, or DNS account.
- `ocliv login --relay <url> --code-file <path>` stores the relay URL once.
- `ocliv 3000` yields a protected `https://<id>.t.<domain>` URL.
- `ocliv mcp 3000 [--name N]` yields an authenticated MCP URL; without
  usable upstream OAuth the command refuses and explains why.
- `ocliv status` / `ocliv doctor` distinguish relay, route, service,
  and public-reachability states; UNKNOWN is never shown as healthy.

## What is blocked

- Provisioning the host, domain, and certificates.
- Running the 24-hour soak and clean-host install proof against it.
- Provider-side ChatGPT registration of an Ocliv endpoint.
- Any anonymous free-for-all registration: explicitly out of scope —
  every tunnel must trace to an enrolled identity with revocable keys.

Until an operator provisions the above, the client flow is verified
only against private staging (see [FUNNEL-LAB.md](FUNNEL-LAB.md)) and
local integration tests — never claimed as public readiness.
