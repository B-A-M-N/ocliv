# Managed auth — release-hardening external qualification (2026-11-12, pass 2)

Second external verification pass, for the 2026-11-12 release-hardening
round (commit `26ac95a`). Same isolation discipline as the first pass:
fresh staging DB, harmless loopback upstream, Tailscale funnel public
edge with its trusted certificate, production Pi untouched. The funnel's
pre-existing (dead) 443 mapping was reused as the relay's backend; no
serve/funnel configuration was added or changed.

## Provenance

```
code         : 26ac95a (+ the five recorded commits above it)
binary       : sha256 919e9c15febc83372540f13e515688e0419c9e5df56ac0dc45b09f3af0b2e3fe
staging DB   : /tmp/ocliv-qual2 (fresh, schema 11, 0700 dir)
public edge  : https://pop-os.tail8d285a.ts.net (trusted cert, ssl_verify_result=0)
```

## Results (all over real public HTTPS)

| # | Check | Result |
|---|-------|--------|
| A1 | no-bearer tool request | 401 + `WWW-Authenticate: Bearer resource_uri="https://pop-os.tail8d285a.ts.net/.well-known/oauth-protected-resource/r/<id>/mcp"` |
| A2 | the challenge's metadata URL is served | 200, bound to this route |
| A3 | presented-but-invalid bearer | same resource_uri + `error="invalid_token"` (distinguished from missing) |
| B1 | `application_type: "web"` with a loopback redirect | 400 `invalid_redirect_uri` — "a web client may not use a loopback redirect" |
| P3-1 | code grant issues access + refresh | both present, `expires_in 3600` |
| P3-2 | refresh token at the tool path | 401 (credential-kind separation) |
| P3-3 | refresh rotation | new access + new refresh; rotated access token works (200 tools/list) |
| P3-4 | replay of the rotated-out token | 400 `invalid_grant` — "refresh token already rotated or revoked" |
| P3-5 | client revocation terminates the lineage | 400 `invalid_grant` — "client is not approved for this route"; grant row revoked |
| P0-2 | cross-key same-tenant reclaim of the named host | refused; original lease ACTIVE, publication intact, 5 `lease_reclaim denied` audit rows |
| Z1 | unauthorized executions | upstream counter moved only on the one authorized tools/call (`pong:ocliv-qual-1`); every denial moved it 0 |

Full positive flow also re-confirmed on this binary: bare-alias
publish (managed default) → DCR → authorize (200 consent page,
route-scoped form action) → operator approve → consent POST → code →
token (resource + RFC 7636 verifier) → tools/list/tools/call over the
public FQDN.

## Findings closed locally that are not remote-reproducible

- **E (malformed pairing expiry)** needs a corrupted database row; the
  durable regression `TestConsumePairingSecretFailsClosedOnBadExpiry`
  proves malformed/empty/truncated/expired all deny.
- **B2 (concurrent DCR crossing the bound)** — the pre-fix sequence was
  shown red under 225 concurrent registrations against the SQL store
  (223 of 225 attempts errored inside the non-atomic window); the fixed
  atomic store admits exactly the bound.
- **C rollback** — the injected-failure test (approval table dropped
  mid-delete) proves the publication survives and the caller sees 500.

## Still not qualified

- A current MCP **SDK** client end-to-end (the flow above is
  curl-driven; SDK client validation remains the next external gate).
- CIMD (Client ID Metadata Documents) — not implemented, not claimed.
- ChatGPT/unattended registration, production promotion, refresh-token
  behavior under a single-hour real expiry window (rotation was proven
  immediately, not after the 1h access-token TTL).
