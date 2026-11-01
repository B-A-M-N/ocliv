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
http redirect_uri 400, plain PKCE 400.

Release plugin ZIP with the live route URL is built per-publication
via `packaging/mcp/build-plugin.sh --release` (never commit a
transient route URL into `plugin/mcp.json`).
