# OclivMCP — ChatGPT plugin package

Portable plugin bundle for an Ocliv-hosted MCP connection (`name`
`ocliv-chatgpt-hosting`, display name OclivMCP, version 0.1.2).
`mcp.json` ships with a clearly-labeled `REPLACE-WITH-*` development
template URL on purpose: replace it with the live, qualified route URL
only after `packaging/mcp/scripts/verify-ingress.sh` passes AND a
manual ChatGPT tool call succeeds (see
`plugin/skills/setup/SKILL.md`).

Never ship a plugin pointing at a temporary route ID from a foreground
publisher that already exited — the connection would be dead on arrival.

Builds: `./packaging/mcp/build-plugin.sh [out-dir]` makes a dev ZIP
(template URL allowed, warns loudly). Release builds take `--release`
and require `OCLIV_QUALIFIED_MCP_URL` plus a fresh
`OCLIV_MCP_QUALIFICATION_RECEIPT` from `scripts/verify-ingress.sh`. That
probe verifies protected-resource metadata, the exact authorization-server
issuer, missing and invalid bearer rejection,
authenticated `tools/list`, and a successful authenticated harmless tool
call. The receipt is tied to the exact endpoint and expires after one hour.
See [`MCP-READINESS-CONTRACT.md`](../../../docs/qualification/MCP-READINESS-CONTRACT.md)
for the distinction between route probing, release qualification, off-LAN
reachability, and hosted-assistant acceptance. Builds reject the retired
`pop-os.tail8d285a.ts.net` host, lab hosts, loopback URLs, and
placeholders. The current public endpoint has not been qualified, so
release packaging must remain blocked until one is supplied.

## Publishing a release ZIP for the current route

The publication identity and route ID are stable across authorized
publisher restarts for the same profile, name, host, and enrolled owner.
They change only when that identity is explicitly removed/recreated or
its identity inputs change. Keep the source `mcp.json` on its placeholder
and build each release ZIP for the currently qualified route URL:

```sh
export OCLIV_QUALIFIED_MCP_URL='https://<qualified-host>/r/<route-id>/mcp'
export OCLIV_MCP_QUALIFICATION_RECEIPT="$HOME/releases/ocliv-mcp/<route-id>/qualification.json"
./packaging/mcp/scripts/verify-ingress.sh --token-file="$HOME/.config/ocliv/upstream-token" \
  --receipt="$OCLIV_MCP_QUALIFICATION_RECEIPT" "$OCLIV_QUALIFIED_MCP_URL"
./packaging/mcp/build-plugin.sh --release "$HOME/releases/ocliv-mcp/<route-id>"
```

Copy the resulting `ocliv-chatgpt-plugin.zip` to
`packaging/mcp/dist/` (git-ignored build output).

## Registering in ChatGPT (operator browser action)

The `/r/<route-id>/mcp` URL is an MCP protocol endpoint, not a web page.
Opening it in a browser or asking ChatGPT to browse to it does not register
or test an MCP connection; a browser's website/error page is not connector
acceptance. Register it only through ChatGPT's custom MCP server flow, after
the public route has passed the ingress and off-LAN checks above.

Current plan availability is documented in
[ChatGPT custom MCP availability and permissions](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt): Business and Enterprise/Edu support custom MCP creation with the required workspace permissions; Pro is limited to read/fetch; Plus/personal accounts do not have custom MCP server creation. This account/workspace permission block is separate from Ocliv endpoint health.

Custom MCP creation requires a Business or Enterprise/Edu workspace
with admin/owner rights (Plus/personal accounts have no such option —
that is a permission block, not an Ocliv defect). The examples below are
historical lab routes, not current production endpoints; their distinct
authorization settings were verified live on 2026-11-02:

**Fixture route** (`.../r/ZyTjyKtv8cWzCILrqcaaVg/mcp`, lab OAuth test
server): OAuth, Default scopes `mcp:tools`, check `offline_access`,
CIMD unavailable (no DCR-substitute metadata advertised), DCR works.
Consent approves `mcp:tools offline_access`; invoke `ping`.

**Management route** (`.../r/oadEddDa1TGACd9aW-762w/mcp`, Skybridge
+ Auth0 `dev-ditre215tiha7ao7`): OAuth, Default scopes `ocliv:read`
(not `mcp:tools` — Auth0 rejects unknown scopes for this audience),
Base scopes `ocliv:read`, `offline_access` unchecked unless the Auth0
API grants it. CIMD unavailable; DCR is NOT open — create the client
in the Auth0 dashboard (Regular Web App, callbacks per ChatGPT form)
and enter its ID/secret in ChatGPT instead.

1. Open `chatgpt.com/plugins`, click `+`, choose Add custom MCP server.
2. Name it `ocliv`; paste the live route URL (`.../r/<route-id>/mcp`).
3. Select OAuth with the per-route settings above, acknowledge the risk.
4. Approve the consent page.
5. In a chat, `@` the plugin and invoke a read-only tool.

Current status (2026-11-02): read-path integration is verified live —
ChatGPT → Auth0 → signed relay management returns status/list/get for
both publication records. Fixture handshake verified end-to-end
through the Funnel edge (register → PKCE consent → JWT →
`pong:ocliv-oauth-lab-1`); Auth0 PRM/AS discovery verified live for
the management route. ChatGPT UI registration of this plugin remains
pending operator action above. The lab IdP
(`tests/staging/mcp-oauth-lab`) is staging-only.
