# metis-idp — test-only RS256 JWT issuer for the Metis MCP transport

TEST-ONLY scaffold, not product code. A stdlib-only Go CLI that mints
RS256 access tokens Metis's `metis mcp serve-http` accepts, so the
Ocliv→Metis composed integration test can run without a real identity
provider.

Metis (mcp_http.go) accepts only RS256/ES256 (HS256 → "unsupported
token alg"), requires a `kid` header, resolves the key from a JWKS
(`METIS_MCP_JWKS_URL`/`METIS_MCP_JWKS_FILE`, cached ~5 min,
refresh-on-unknown-kid), and verifies per request:
`iss` == `METIS_MCP_ISSUER`, non-empty `sub`, `aud` == exact resource,
`exp` (+60s leeway), optional `nbf` (+60s leeway), and a space-separated
`scope`/`scp` containing the required tool scope.

Metis remote scopes (nothing implies another): `metis:message`,
`metis:provision`, `metis:input`, `metis:stop`. `tools/list` and the
read-only tools need no scope; `metis_provision` needs `metis:provision`,
`metis_terminal_input`/`metis_send` need `metis:input`, `metis_session_stop`
needs `metis:stop`.

## Build

```sh
go build -o /tmp/metis-idp ./tests/staging/metis-idp
```

## Usage

```sh
# 1. generate a keypair + JWKS into a private dir (mode 0700/0600)
JWKS=$(metis-idp genkey -dir "$TMP" -kid t1)   # prints $TMP/jwks.json

# 2. start Metis against the JWKS file and a publisher handoff file
METIS_MCP_ISSUER=https://idp.example/oauth \
METIS_MCP_JWKS_FILE="$TMP/jwks.json" \
METIS_MCP_RESOURCE_FILE="$TMP/resource.txt" \
metis mcp serve-http --listen 127.0.0.1:PORT

# 3. bind the route URL, then mint and present a token
printf 'https://host/r/AbC123XyZ/mcp' > "$TMP/resource.txt"   # chmod 600
TOK=$(metis-idp token -privkey "$TMP/key.pem" \
  -iss https://idp.example/oauth -sub op-1 \
  -aud https://host/r/AbC123XyZ/mcp -scope "metis:message")
curl -X POST http://127.0.0.1:PORT/mcp -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOK" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}'
```

`token` defaults produce a valid token; the following flags mint
deliberately bad tokens for negative tests:

| Defect | Flags |
|---|---|
| wrong audience | `-aud https://evil.example/r/other/mcp` |
| wrong issuer | `-iss https://evil.example/oauth` |
| expired | `-exp -60` |
| not yet valid | `-nbf 7200` |
| unknown kid | `-kid no-such-key` |
| HS256 (rejected alg) | `-alg HS256` |
| missing scope | `-no-scope` |
| insufficient scope | `-scope metis:read` |
| malformed | `-malformed` |

## Verified behaviour (live Metis binary, f58453d)

- Unbound (resource file absent) → discovery & `/mcp` **503**, fail closed.
- Bound resource (mode 0600) → discovery **200**; valid-token `initialize`
  and `tools/list` → **200**; `tools/list` returns the full Metis tool set.
- Wrong aud / expired / wrong iss / unknown kid / HS256 / nbf-not-yet /
  malformed → **401**, no tool executes.
- Missing / insufficient scope on a scoped `tools/call` → HTTP **200** with
  JSON-RPC `-32602 "token lacks <scope> scope"`; no tool executes (auth
  passed at the HTTP layer; only scope enforcement rejected — this is the
  transport's real contract, not a 401).
- Resource file group/world-writable (mode & 0022 != 0) → **503** fail closed;
  removing the file mid-run → **503** (stale binding never reused); restoring
  0600 → **200** again (file re-read every request).

## Safety

Never reads/writes outside the caller-chosen paths; no network egress;
fixtures only. Key and JWKS are written 0600.