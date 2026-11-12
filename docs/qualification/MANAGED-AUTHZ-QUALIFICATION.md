# Managed Authorization — External Qualification Runbook

Status: **NOT EXECUTED** — operator-gated. No result below is a claim; every
row in the verdict table is a place for evidence, not a prediction.

This runbook qualifies the relay-side authorization mode added in
`docs/ADR-local-mcp-auth.md`: a route whose upstream has no native OAuth,
fronted by the relay acting as the Authorization Server.

It is written so an operator can execute it end to end without reading the
implementation. Every step names its **oracle** (what output proves it) and
its **fail-closed expectation** (what a broken build does instead).

## 0. What this does and does not qualify

**Does:** the complete authorization flow over real infrastructure — public
TLS edge, route-scoped discovery, DCR, PKCE, operator approval, token
enforcement at admission, revocation, key rotation.

**Does not:** ChatGPT registration, a production IdP, per-tool
permissioning, multi-IdP federation, or scale testing. Those stay out of
scope by design (ADR §2).

**Not a substitute for:** the local suites. `go test ./internal/...` and
`go test ./tests/integration/` must be green before this starts; a local
red here means the runbook was run against a broken build.

## 1. Prerequisites (operator-gated)

| # | Prerequisite | Why it blocks |
|---|--------------|---------------|
| P1 | A public hostname with DNS pointing at the edge | The token audience is the route URL; a non-public host cannot be reached by an external client |
| P2 | A valid cert for that host (Caddy ACME or managed TLS) | `--insecure`/`InsecureSkipVerify` are refused by construction; a self-signed edge needs `--cacert` and is a weaker oracle |
| P3 | The relay deployed with `--mcp-host` set to that exact FQDN | Without it, route creation fails closed with 409 |
| P4 | A publisher machine that can reach the relay over WSS | The route must be bound to a live lease |
| P5 | A local MCP server for the upstream (read-only, no private data) | Do not qualify against anything with real data |
| P6 | Shell access to the relay host for `ocliv authz ...` | Approval is a local operator action on the relay store |
| P7 | A throwaway MCP client (curl is sufficient) | DCR + PKCE must be driven by something other than the relay's own tests |

If any prerequisite is unmet, stop. The run is **BLOCKED**, not partially
passed.

## 2. Topology

```
external client (public internet)
  -> https://<fqdn>/                       (TLS edge: Caddy or managed TLS)
  -> relay 127.0.0.1:<port>               (--mcp-host <fqdn>)
       PRM  /.well-known/oauth-protected-resource/r/<id>/mcp
       AS   /.well-known/oauth-authorization-server/r/<id>/oauth
       OAuth /r/<id>/oauth/{authorize,token,register,revoke,jwks}
  -> agent WSS+yamux
  -> upstream 127.0.0.1:<local>            (local MCP server, no OAuth)
```

Managed routes require path ingress: the token audience is route-scoped, so
the wildcard-hostname surface cannot carry them.

## 3. Procedure

### 3.1 Relay and route

```sh
# Relay host. Loopback only; the edge is the public listener.
ocliv relay serve --listen 127.0.0.1:8080 --data /var/lib/ocliv \
  --domain <domain> --mcp-host <fqdn>
```

```sh
# Publisher host: enroll once, then publish with relay-terminated auth.
ocliv login --relay https://<fqdn> --code-file -
ocliv mcp publish --local http://127.0.0.1:8765/mcp \
  --auth ocliv-managed --name managed-qual
```

**Oracle:** the publish prints `✓ route registered (managed authorization:
the relay is the Authorization Server)` followed by the approval commands.
**Fail-closed:** an unconfigured `--mcp-host` gives 409 at route creation;
`--auth upstream-oauth` with a non-OAuth upstream fails strict discovery.

Record the printed endpoint: `https://<fqdn>/r/<id>/mcp`.

### 3.2 Discovery is route-scoped

```sh
curl -fsS https://<fqdn>/.well-known/oauth-protected-resource/r/<id>/mcp
curl -fsS https://<fqdn>/.well-known/oauth-authorization-server/r/<id>/oauth
```

**Oracle:** PRM `resource` equals the endpoint URL exactly, and
`authorization_servers[0]` equals `https://<fqdn>/r/<id>/oauth`. AS
`issuer` equals that same value and each `*_endpoint` is issuer + the
expected suffix (`/authorize`, `/token`, `/register`, `/revoke`, `/jwks`).
**Fail-closed:** a mismatch means the advertised endpoints do not match the
route's real paths — clients will construct wrong URLs.

### 3.3 Publication-level boundary (deny by default)

```sh
# No bearer, no token: must be refused before any upstream call.
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://<fqdn>/r/<id>/mcp
```

**Oracle:** `401`. **Fail-closed:** anything else means an unauthenticated
fallback exists. Also confirm the upstream logged zero requests.

### 3.4 Client registration and operator approval

```sh
# Register a client (RFC 7591 shape).
curl -fsS -X POST -H 'Content-Type: application/json' \
  -d '{"client_name":"qual","redirect_uris":["http://127.0.0.1:59999/cb"],"token_endpoint_auth_method":"none"}' \
  https://<fqdn>/r/<id>/oauth/register
# -> {"client_id":"..."}

# Start authorization. The canonical resource is REQUIRED (MCP spec).
curl -sS -o /dev/null -w '%{http_code}\n' -D - \
  "https://<fqdn>/r/<id>/oauth/authorize?client_id=<cid>&redirect_uri=http%3A%2F%2F127.0.0.1%3A59999%2Fcb&response_type=code&code_challenge=<S256>&code_challenge_method=S256&resource=https%3A%2F%2F<fqdn>%2Fr%2F<id>%2Fmcp"
```

**Oracle:** `200` with an HTML **consent page** (a form posting to
`/oauth/consent`). **No** `Location` header. **Fail-closed:** a `302` with
a code before the operator consents means the publication boundary is not
the gate. Confirm the page does **not** contain the pairing credential and
that the credential appears nowhere in the request URL.

```sh
# Relay host: the operator issues the pairing credential for the pending
# grant. --tenant and --route are REQUIRED.
ocliv authz pending --data /var/lib/ocliv
ocliv authz approve --data /var/lib/ocliv --client <cid> \
  --tenant <tenant> --route <id>
```

**Oracle:** `approved client <cid> ...` followed by the **pairing
credential**, printed once.

**Deliver the credential to the client operator over a private channel.**
It is submitted in the consent form body, never in a URL.

**Fail-closed:** approving without `--tenant`/`--route` is refused (an
ambiguous approval is never guessed); approving a client with no pending
grant is refused.

### 3.5 Full client flow

```sh
# Complete consent by POSTing the credential against the one-time challenge.
# -> 302, Location: http://127.0.0.1:59999/cb?code=...&state=xyz
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'challenge=<challenge-from-the-page>' \
  --data-urlencode 'client_id=<cid>' \
  --data-urlencode 'redirect_uri=http://127.0.0.1:59999/cb' \
  --data-urlencode 'code_challenge=<S256>' \
  --data-urlencode 'resource=https://<fqdn>/r/<id>/mcp' \
  --data-urlencode 'pairing_secret=<credential>' \
  https://<fqdn>/r/<id>/oauth/consent

# Exchange with PKCE. resource is required and must match the route.
curl -fsS -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'code=<code>' \
  --data-urlencode 'client_id=<cid>' \
  --data-urlencode 'redirect_uri=http://127.0.0.1:59999/cb' \
  --data-urlencode 'code_verifier=<verifier>' \
  https://<fqdn>/r/<id>/oauth/token
```

```sh
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" \
  -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://<fqdn>/r/<id>/mcp
```

**Oracle:** `200` with a real `tools/list` result. **Fail-closed:** a token
minted without an ACTIVE grant must be refused at admission.

### 3.6 Negative paths

Each case uses a **freshly minted token for a second, independent client**
(so a token invalidated by an earlier section can never silently satisfy a
later one). Every denial must show **both** the status and zero upstream
executions.

| # | Case | Construction | Expected |
|---|------|--------------|----------|
| N1 | Missing bearer | omit `Authorization` | 401 |
| N2 | Tampered bearer | append a character to a valid token | 401 |
| N3 | Wrong audience | token minted for a *different* route | 401 |
| N4 | Replayed code | exchange the same `code` twice | 400 `invalid_grant` |
| N5 | Wrong PKCE | exchange with a mismatched `code_verifier` | 400 `invalid_grant` |
| N6 | No pairing secret | authorize an approved client without `pairing_code` | 403 `access_denied`, no redirect |
| N7 | Wrong pairing secret | authorize with a bad `pairing_code` | 403 `access_denied`, no redirect |

**Status-code note.** N1–N3 and N6–N7 are authorization failures → 401/403.
N4–N5 are **token-endpoint** errors → `400 invalid_grant` per RFC 6749 §5.2.
Expecting 401 there would be wrong; the runbook previously did.

**Fail-closed:** a wrong-audience token accepted anywhere means audience
binding is not enforced per route.

### 3.7 Revocation is immediate (OAuth token revocation, RFC 7009)

Use a **dedicated client T3** with a currently valid token. Do not reuse a
token invalidated above.

```sh
# T3: register, approve, obtain a fresh token (as in 3.4-3.5).
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOK3" ... https://<fqdn>/r/<id>/mcp   # -> 200

curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$TOK3" \
  --data-urlencode 'token_type_hint=access_token' \
  https://<fqdn>/r/<id>/oauth/revoke                                  # -> 200

# Immediately denied, on the NEXT request — not at expiry.
curl ... -H "Authorization: Bearer $TOK3" ...                        # -> 401
```

**Oracle:** 401 on the next request, zero upstream executions, and a second
client T4's token still returns 200. An invalid token presented to
`/oauth/revoke` must also return 200 (RFC 7009 §2.2).
**Fail-closed:** still 200 after revocation means the endpoint is
advertised but not implemented.

### 3.8 Publisher restart preserves approval

Run this **before** key rotation so the token is still valid.

Use a client T6 whose grant is ACTIVE and whose token is still valid.

```sh
# Stop the publisher, then republish the same name.
ocliv mcp publish --local http://127.0.0.1:8765/mcp \
  --auth ocliv-managed --name managed-qual
# Present T6's SAME pre-restart token (no re-approval, no new credential).
```

**Starting state required:** T6 has an ACTIVE grant and a valid, unexpired,
unrevoked token minted **before** the restart. Do not reuse a token from
§3.6/§3.7.

**Oracle:** the endpoint is byte-identical, the token still works, and
`ocliv authz list` still shows exactly one `active` grant for T6.
**Fail-closed:** a new route id, or a working token after an unapproved
republish, means approval state is not bound to route identity.

### 3.9 Issuer key rotation

Use a **separate client T5** with a currently ACTIVE grant and a valid
pre-rotation token, minted fresh after §3.8. Do not reuse any earlier token.

```sh
# Relay host. Confirm the grant first.
ocliv authz list --data /var/lib/ocliv          # T5 must be status=active
# Present T5's live token once -> 200
ocliv authz rotate-key --data /var/lib/ocliv
# Present the SAME pre-rotation token -> must be 401 immediately.
```

**Starting state required:** T5 has an ACTIVE grant, a valid unexpired
token minted after §3.8, and its jti is not revoked.

**Oracle:** 401 on the next request, with no relay restart. **Fail-closed:**
still 200 means the running relay kept the retired key in memory.

### 3.10 Incompatible mode change is refused

```sh
# Same lease, different profile: must not silently rebind the stable URL.
# Publish the same name with the other profile.
ocliv mcp publish --local http://127.0.0.1:8765/mcp \
  --auth upstream-oauth --name managed-qual
```

**Oracle:** route creation is refused (409) because the lease's access mode
does not support the requested profile, the route id is unchanged, and T6's
token still works. **Fail-closed:** a silent rebind would mean an
authentication-mode change happened without authorization.

### 3.11 Teardown

```sh
ocliv mcp unpublish --lease <lease-id>
tail -f <upstream access log>   # confirm zero further requests
ocliv authz list --data /var/lib/ocliv   # confirm the grant row is gone/revoked
```

**Fail-closed:** the route must stop serving; a retained publication is
offline (`503`) and must not forward.

## 4. Verdict table (fill during the run)

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| 1 | Public TLS, no `-k` | | |
| 2 | Route-scoped PRM/AS match the endpoint | | |
| 3 | No-bearer denied, zero upstream hits | | |
| 4 | Registration without approval issues no code | | |
| 5 | Approval requires explicit tenant+route; issues one pairing credential | | |
| 6 | Pending approval renders a consent page; no credential in the URL | | |
| 7 | DCR → consent → PKCE+resource → token → authorized call | | |
| 8 | Consented grant completes the standard flow with standard params only | | |
| 9 | Negative paths N1–N7 (401/403/400 as specified), zero executions | | |
| 10 | OAuth token revocation (RFC 7009) immediate; unrelated client unaffected | | |
| 11 | Revoked client's existing token and previously issued code both refused | | |
| 12 | Token without a jti is refused at admission | | |
| 13 | Key rotation immediate, from an ACTIVE grant + live token | | |
| 14 | Republish preserves route id + approval, same token still valid | | |
| 15 | Incompatible mode change refused (409) | | |
| 16 | Teardown stops serving | | |

**Overall disposition:** PASS only if every row is PASS with recorded
evidence. Any FAIL is a defect, not a qualification gap to be argued away.

## 5. Evidence standard

- Paste the actual command and its actual output; "it worked" is not
  evidence.
- For every denial, show both the status code **and** the upstream access
  log proving zero executions — the counter, not the status, is the oracle.
- Record the relay version (`ocliv version`) and the route id.
- Redact tokens, codes, and enrollment codes. Refer to them by label.
- A check that could not be exercised is **NOT VERIFIED**, never PASS.

## 6. Known limits of this runbook

- It does not prove the upstream's own behavior beyond receiving a
  relay-minted identity header. The upstream's use of that identity is
  out of scope (ADR §5: loopback is not isolation).
- It does not prove a provider-issued IdP or ChatGPT registration.
- It does not prove behavior under load; see `docs/qualification/CHAOS-BATCH.md`.
