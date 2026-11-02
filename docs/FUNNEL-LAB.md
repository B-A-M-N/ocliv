# Funnel lab (throwaway public-ingress test)

Lab-only procedure. Funnel is NOT a product ingress path; see
[OPERATOR.md](/home/bamn/ocliv/docs/OPERATOR.md). Tear down with
`tailscale funnel reset` when done.

## Layout (outside the repo; never commit)

`~/ocliv-funnel-lab/`: `ocliv` + `mcp-auth-fixture` binaries, `relay.log`,
`fixture.log`, `publish.log`, `resource.url`, `token` (0600), `data/`,
`pubhome/`.

## Run

```sh
cd ~/ocliv-funnel-lab
./mcp-auth-fixture -port 18765 >>fixture.log 2>&1 &
./ocliv relay serve --listen 127.0.0.1:18082 --data ./data \
  --domain funnel-lab.test \
  --relay-host pop-os.tail8d285a.ts.net \
  --mcp-host pop-os.tail8d285a.ts.net >>relay.log 2>&1 &
./ocliv relay issue-enroll --data ./data --tenant lab   # one-time code
HOME=$PWD/pubhome ./ocliv login --relay https://pop-os.tail8d285a.ts.net --code-file <(code)
HOME=$PWD/pubhome setsid -f ./ocliv mcp publish \
  --local http://127.0.0.1:18765/mcp --auth upstream-oauth \
  --name funnellab --resource-file $PWD/resource.url >>publish.log 2>&1
sudo tailscale funnel 18082   # operator action; prints public https URL
```

## Verify (from any network)

```sh
R=$(cat resource.url); T=$(cat token)
curl $R -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' # expect 401
curl $R -X POST -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H "Authorization: Bearer $T" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' # expect 200
```

## Restart / recovery

- Fixture or tunnel dies: restart that process only; relay keeps state.
- Relay dies: restart with same `--data`; leases re-attach on agent resume.
- Route revoked (`mcp unpublish`): re-run `mcp publish` (route ID changes).
- `tunnel credential rejected` usually means the lease lapsed (check
  `leases/` status in the relay DB), not a bad agent key: move the stale
  `leases/lse-*.json` aside and republish fresh (stable route IDs kept).
  Verify the key with `SELECT id,status FROM agent_keys`.
- Reboot wipes `/tmp` and all services. Restore order: relay →
  Skybridge (`:18772`) → publisher → `sudo tailscale funnel --bg 18082`;
  the publisher only attaches once the public URL answers.
  Rollback build: `~/ocliv-funnel-lab/rollback/dist-de31fd5`.

## Shutdown

```sh
HOME=$PWD/pubhome ./ocliv mcp unpublish   # removes public route (verify 404)
kill <tunnel-pid> <fixture-pid> <relay-pid>
sudo tailscale funnel reset
```

Fixture bearer in `token` is lab-only; rotate per run.

## OAuth lab (ChatGPT-compatible)

Relay from this tree admits route-scoped OAuth shapes
(`/.well-known/oauth-authorization-server/r/<id>/oauth`,
`/r/<id>/oauth/{authorize,token,register}`) for upstream-oauth leases;
see `tests/staging/mcp-oauth-lab/` (lab-only IdP+RS, HS256 JWT, DCR,
S256 PKCE — not a production IdP).

```sh
head -c 48 /dev/urandom | base64 > oauth-secret && chmod 600 oauth-secret
MCP_OAUTH_SECRET=$(cat oauth-secret) MCP_RESOURCE_FILE=$PWD/resource.url \
  setsid -f ./mcp-oauth-lab -port 18767 >>oauth-lab.log 2>&1 &
HOME=$PWD/pubhome setsid -f ./ocliv mcp publish \
  --local http://127.0.0.1:18767/mcp --auth upstream-oauth \
  --name funnel-oauth --resource-file $PWD/resource.url >>publish.log 2>&1
```

Full scripted check: resource metadata → AS metadata → register →
consent GET → approve POST → token → `tools/call ping` with the JWT
(expect `pong:ocliv-oauth-lab-1`); negatives: no/bad bearer 401,
http redirect_uri 400, plain PKCE 400. Lab scope note: request
`mcp:tools` (bare `mcp` is rejected by the fixture); register requires an
https redirect_uri. Stale `leases/*.json` pointing at a terminal lease
breaks `mcp publish` resume — move it aside and republish fresh (stable
route IDs are retained).

Release plugin ZIP with the live route URL is built per-publication
via `packaging/mcp/build-plugin.sh --release` (never commit a
transient route URL into `plugin/mcp.json`).

## Auth0 mgmt route (operator checklist, 2026-11-02)

Live route `.../r/oadEddDa1TGACd9aW-762w/mcp` (Skybridge `:18772`,
scopes `ocliv:read`/`ocliv:write`, audience = route URL). ChatGPT needs:

- Application client (Regular Web App) with the exact callback URL from
  ChatGPT's custom-MCP form in Allowed Callback URLs (verbatim match;
  mismatch fails at `/authorize/resume`).
- `ocliv` API granting `ocliv:read` (and `ocliv:write` when writes are
  qualified); RS256; "Resource Parameter Compatibility" + "Include
  Issuer in Authorization Responses" toggles on; **login connection
  enabled for the app** (missing piece found 2026-11-02).
- ChatGPT form: Default + Base scopes `ocliv:read` (not `mcp:tools`),
  client ID/secret pasted (no open DCR on Auth0 Free), `offline_access`
  unchecked unless granted.
- Skybridge env: `OCLIV_TRUSTED_ISSUERS` must contain the Auth0 issuer
  or `verify-publication` reports `ISSUER_UNTRUSTED`.
