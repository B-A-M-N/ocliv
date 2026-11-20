---
name: setup
description: Connect ChatGPT to an Ocliv-hosted MCP server over a qualified route (publish, verify, paste URL, confirm tools).
---
# Ocliv MCP setup skill

This skill connects ChatGPT to an Ocliv-hosted MCP server. Do it only
after the route is qualified live (see
`packaging/mcp/scripts/verify-ingress.sh`).

1. Publish with strict discovery and keep the publisher running:
   `ocliv mcp publish --local http://127.0.0.1:PORT/mcp --auth
   upstream-oauth --ttl 2h --strict-discovery --resource-file
   /path/to/resource.url`
2. Record the printed route URL. It is an opaque identifier, not a
   secret — but it must stay stable: do not ship a plugin pointing at a
   route whose publisher already exited or whose lease expired.
3. Replace the `url` in `mcp.json` with that exact route URL (including
   any non-443 `:port`).
4. In ChatGPT: Plugins → Add custom MCP server → paste the URL,
   complete OAuth against YOUR upstream issuer, confirm `tools/list`
   shows only the expected tools, and invoke one read-only tool.
5. Only after a live tool call succeeds through ChatGPT is the
   connection qualified. A green `verify-ingress.sh` alone is not
   ChatGPT qualification.

Security: the upstream MCP server enforces OAuth (issuer, audience,
expiry, scopes). Ocliv forwards `Authorization` untouched and never
sees the token contents. Revoke with `ocliv access revoke`; the route
then denies with 503.
