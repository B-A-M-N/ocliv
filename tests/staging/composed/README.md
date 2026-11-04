# Composed demo — Ocliv + Metis (+ Locus, operator-gated)

`run-composed.sh` stands up a real composed chain on one machine and
proves the authenticated public-route contract:

```
visitor (curl)
  -> Ocliv public TLS edge          (socat stand-in for Caddy, loopback)
  -> Ocliv relay                    (loopback, path route /r/<id>/mcp)
  -> Ocliv agent                    (publish tunnel, loopback)
  -> Metis MCP server               (real binary, /mcp, loopback)
       -> Metis Muse worker -> Locus -> provider   [NOT EXERCISED]
```

Locus sits **behind** Metis as its inference gateway. It is an external,
operator-gated dependency: this script never starts, stops, reconfigures,
or writes to a Locus instance. The inference leg is always reported as
`Locus inference leg: NOT VERIFIED (operator-gated)`.

`docs/COMPOSED-DEMO.md` records the topology, ownership boundaries, and
the exact scope of what the script proves.

## Prerequisites

| Requirement | Why |
|---|---|
| bash 5+ | `set -euo pipefail`, arrays, `/dev/tcp` port probe |
| Go toolchain | builds `ocliv` and the committed `tests/staging/metis-idp` fixture |
| `curl`, `openssl`, `socat`, `python3` | HTTP assertions, lab CA/cert, TLS edge, JSON parsing |
| a Metis binary | the real MCP server under test, supplied via `METIS_BIN` |

No repository, database, key, or certificate is created inside the Ocliv
checkout. Everything generated lands in a `0700` directory under
`COMPOSED_TMP_ROOT` and is deleted on exit.

### Obtaining a Metis binary

Build from a Metis checkout (outside this repo) and point `METIS_BIN` at
the result:

```sh
git clone <metis-repo> metis-src && cd metis-src
./build.sh                       # or: go build -buildvcs=false -o metis .
```

`-buildvcs=false` is what the Metis repo's own `build.sh` uses. Use plain
`go build -o metis .` when your checkout is a normal working tree and VCS
stamping works there.

## Environment variables

Every path and port is overridable. Defaults avoid ports already used by
long-running lab services on a developer host (`18443`, `18769`,
`18796`, `18799` are deliberately not used).

| Variable | Default | Meaning |
|---|---|---|
| `METIS_BIN` | *(required)* | path to an executable Metis binary; the script exits 2 if unset |
| `COMPOSED_TMP_ROOT` | `${TMPDIR:-/tmp}` | parent for the private work dir (`mktemp -d`) |
| `EDGE_PORT` | `19443` | public TLS edge listener (socat), also the route URL port |
| `RELAY_PORT` | `19470` | relay loopback HTTP listener |
| `HEALTH_PORT` | `19471` | relay loopback health listener |
| `METIS_PORT` | `19480` | Metis MCP loopback listener |
| `PUBLIC_HOST` | `127.0.0.1` | relay authority, `--mcp-host`, and cert SAN (lab only) |
| `DOMAIN` | `ocliv.test` | relay `--domain`; placeholders `example.com/net/org` are refused by the relay |
| `PUBLISH_NAME` | `composed-demo` | `mcp publish --name` |
| `PUBLISH_TTL` | `15m` | `mcp publish --ttl` |
| `ISSUER` | `https://idp.example/oauth` | `METIS_MCP_ISSUER` and token `iss` |
| `SCOPES` | `metis:message metis:provision metis:input metis:stop` | scope claim for the valid token |
| `STARTUP_WAIT_SECS` | `30` | per-component readiness budget |
| `PUBLISH_WAIT_SECS` | `60` | budget for publish to print an active route |
| `KEEP_ARTIFACTS` | `0` | `1` keeps the work dir and prints its path |
| `LOCUS_BASE_URL` | *(empty)* | optional Locus base URL, e.g. `http://127.0.0.1:<port>/v1`; only reported, never contacted unless the probe below is enabled |
| `LOCUS_READONLY_PROBE` | `0` | `1` performs a single `GET <LOCUS_BASE_URL>/v1/models` (read-only reachability, **not** inference proof) |

All four ports must be free on `127.0.0.1`; the script refuses to start
otherwise.

## Run

From the Ocliv repo root:

```sh
METIS_BIN=/path/to/metis ./tests/staging/composed/run-composed.sh
```

The script:

1. builds `ocliv` and `tests/staging/metis-idp` into the work dir
   (falls back to `-buildvcs=false` when run from a linked git worktree,
   where Go cannot find a VCS root for main packages);
2. generates a one-day lab CA and a `127.0.0.1`-SAN server certificate;
3. starts Metis with an isolated `METIS_STATE`, JWKS file, and resource
   binding file;
4. starts the relay loopback-only with `--mcp-host`/`--mcp-port`, then a
   `socat` TLS edge in front of it;
5. mints a one-time enrollment code, logs in the agent through the edge;
6. publishes the Metis server with `--auth upstream-oauth` and the
   resource-file handoff, waiting for a verified route URL;
7. mints RS256 tokens with the committed test IdP and asserts the
   contract through the public route.

## Expected output

```text
== build ==
   ocliv + metis-idp built
...
   published route: https://127.0.0.1:19443/r/<route-id>/mcp
PASS  publish verified OAuth discovery (resource == route URL)
PASS  resource binding handoff equals route URL
PASS  protected-resource metadata answered 200
PASS  discovery advertises the published resource
PASS  tools/list with valid bearer answered 200
PASS  tools/list returned exactly the 15 metis_* tools
PASS  wrong-audience bearer rejected with 401
PASS  missing bearer rejected with 401
PASS  MCP-Protocol-Version 2026-07-28 answered 200
PASS  MCP-Protocol-Version 2025-06-18 rejected with 400

Locus inference leg: NOT VERIFIED (operator-gated)
...
RESULT: PASS
```

Exit codes: `0` all assertions passed, `1` a setup step or assertion
failed, `2` missing prerequisite or bad environment (including a port
already in use).

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `METIS_BIN is not set` / `not an executable file` | binary not supplied | point `METIS_BIN` at a Metis build |
| `port … is already in use` | default collides with a running service | override that `*_PORT` |
| `Metis did not become ready` | wrong binary or missing `/mcp` support | check `metis-master mcp serve-http --help`; use a Metis build with `serve-http` |
| `relay health did not report ready` | port race, unwritable data dir, or relay refused `--domain` | re-run; read the printed relay log |
| `TLS edge did not answer` | `socat` missing or port taken between checks | install socat / change `EDGE_PORT` |
| `agent login failed` | relay unreachable through the edge, or code expired | re-run (each run uses a fresh relay DB and code) |
| `publish did not print an active route URL` | strict OAuth discovery failed (resource mismatch/unreachable) or upstream not answering | inspect the printed publish log; confirm `LOCAL`/edge host/port alignment |
| `FAIL … tools/list returned exactly the 15 metis_* tools` | Metis build exposes a different tool set | update the expected list only with evidence of the new contract |
| `FAIL … wrong-audience bearer rejected with 401` | Metis is not validating `aud`, or the resource file was not bound | treat as a real defect: stop and investigate |

No failure path fakes success: every assertion is a live HTTP result and
any `FAIL` makes the run exit non-zero.

## Cleanup

Cleanup is automatic (trap on `EXIT`/`INT`/`TERM`): publish, edge,
relay, and Metis are terminated and the work dir is removed. Set
`KEEP_ARTIFACTS=1` to retain logs and generated material for inspection;
the directory is private (`0700`) and must not be committed or copied
into the repo. Generated keys, JWKS, tokens, certificates, the relay
database, and logs never enter the repository, and no token is ever
printed.

If a run is killed with `SIGKILL`, remove leftovers manually:

```sh
pkill -f 'composed-demo' || true     # only your own lab processes
rm -rf "${TMPDIR:-/tmp}"/composed-demo.*
```

Never use a broader pattern: a live relay, agent, or Locus instance on
this host is not yours to stop.

## What this does not prove

- **Locus inference** — no Muse worker turn is run; `NOT VERIFIED
  (operator-gated)`. A `LOCUS_READONLY_PROBE=1` result is reachability
  only.
- **Real public ingress** — the TLS edge is a loopback `socat` stand-in
  for Caddy. Public DNS, ACME issuance, and internet reachability stay
  `NOT VERIFIED (operator-gated)`.
- **Revocation through the public route** — the script publishes and
  asserts the serving contract; revoke/unpublish paths are covered by
  the repo's integration suites, not this harness.
- **A production IdP** — tokens come from `tests/staging/metis-idp`, a
  test-only RS256 issuer.
