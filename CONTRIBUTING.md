# Contributing to Ocliv

Thank you for your interest in contributing to Ocliv.

## Scope & Design Boundaries

Before proposing a feature or architectural change, read:

- [AGENTS.md](AGENTS.md) — non-negotiable engineering invariants and validation gates
- [docs/specs/ocliv_anti_spec.md](docs/specs/ocliv_anti_spec.md) — explicit non-goals and complexity boundaries

## Development Requirements

- **Go 1.26+** (`CGO_ENABLED=0`)
- **Linux (`systemd`)** for full persistent-hosting and staging lifecycle tests

## Before Submitting a Pull Request

All pull requests must pass the repository's validation gates cleanly:

```sh
./scripts/check-repo-hygiene.sh
test -z "$(gofmt -l cmd internal packaging tests)"
go vet ./...
git diff --check
go test ./... -count=1 -timeout=420s
go test -race ./internal/cli ./internal/protocol ./internal/identity ./internal/config ./internal/agent ./internal/store ./internal/lease ./internal/setup -count=1 -timeout=300s
go test -race ./internal/relay -count=1 -timeout=600s
```

## Non-Negotiable Architecture Rules

- **No second authority source:** SQLite on the relay is the sole admission and revocation authority.
- **No bypass of revocation:** Revoked keys, leases, publications, grants, clients, and trust policies must fail closed and stay revoked across restarts and restores.
- **No weakened TLS/auth validation:** Never disable certificate verification, accept non-HTTPS trust callbacks, or bypass signed `mgmt_body_sig_v2` mutations.
- **Forward-only migrations:** Schema changes must be strictly forward-only and rollback-guarded.
- **No unnecessary services/processes:** Do not introduce external databases, Docker dependencies, or sidecar daemons without a concrete architectural requirement.

## Security Reports

**Do not open public GitHub issues for security vulnerabilities.** See [docs/SECURITY.md](docs/SECURITY.md) for responsible disclosure guidance.

## Licensing & Contributor License Agreement

Ocliv is dual-licensed under `AGPL-3.0-only` and a separate commercial license (see [LICENSING.md](LICENSING.md)). To preserve the project's ability to offer both open-source and commercial licenses, non-trivial external contributions require acceptance of the Ocliv Contributor License Agreement (CLA), under which contributors retain copyright in their contributions while granting the project the rights necessary to distribute and relicense the combined work.
