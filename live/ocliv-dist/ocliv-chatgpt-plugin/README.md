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
