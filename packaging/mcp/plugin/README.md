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
and refuse any unresolved `REPLACE-WITH-*` placeholder, lab host, or
loopback URL — a release ZIP always points at a qualified live route.

## Publishing a release ZIP for the current route

Route IDs rotate on every `mcp publish`, so the source `mcp.json`
keeps the placeholder and each release ZIP is built per-publication
(never commit a transient route URL):

```sh
R=$(cat ~/ocliv-funnel-lab/resource.url)   # active publication
rm -rf /tmp/plugin-build && cp -r packaging/mcp /tmp/plugin-build
cd /tmp/plugin-build
python3 - "$R" <<'EOF'
import json, sys
with open("plugin/mcp.json") as f:
    m = json.load(f)
m["mcpServers"]["ocliv"]["url"] = sys.argv[1]
with open("plugin/mcp.json", "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
EOF
./build-plugin.sh --release /tmp/plugin-out   # must print validation OK
```

Copy the resulting `ocliv-chatgpt-plugin.zip` to
`packaging/mcp/dist/` (git-ignored build output).

## Registering in ChatGPT (operator browser action)

Custom MCP creation requires a Business or Enterprise/Edu workspace
with admin/owner rights (Plus/personal accounts have no such option —
that is a permission block, not an Ocliv defect):

1. Open `chatgpt.com/plugins`, click `+`, choose Add custom MCP server.
2. Name it `ocliv`; paste the live route URL (`.../r/<route-id>/mcp`).
3. Select OAuth, acknowledge the risk prompt.
4. Approve the consent page (scope `mcp:tools offline_access`).
5. In a chat, `@` the plugin and invoke `ping`.

Current lab status (2026-11-01): public OAuth handshake verified
end-to-end through the Funnel edge (register → PKCE consent → JWT →
`pong:ocliv-oauth-lab-1`); real ChatGPT registration pending operator
action above. The lab IdP (`tests/staging/mcp-oauth-lab`) is
staging-only — production needs a real identity provider.
