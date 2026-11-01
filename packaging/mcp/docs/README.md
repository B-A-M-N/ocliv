# Ocliv MCP runtime package

Self-hosted tunnel + authenticated MCP ingress. One public relay serves
many publishers; each publisher makes only outbound connections.

Start with `docs/MCP-HOSTING.md` (product contract), then
`config/*.example`, `caddy/`, `systemd/`. `scripts/verify-local.sh` and
`scripts/verify-ingress.sh` encode the qualification probes; both fail
closed and print no secrets.

`bin/mcp-auth-fixture` is the staging MCP server used for qualification
(loopback-only, single read-only `ping` tool, bearer enforced). It is a
test double, not a production MCP server: publish your own audited
HTTP MCP server with `--local` for real use.
