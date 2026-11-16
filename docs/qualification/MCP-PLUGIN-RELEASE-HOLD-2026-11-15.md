# MCP plugin release hold — 2026-11-15

The ZIP previously at `packaging/mcp/dist/ocliv-chatgpt-plugin.zip` is
superseded and must not be distributed. It embeds the retired endpoint
`https://pop-os.tail8d285a.ts.net/r/ZyTjyKtv8cWzCILrqcaaVg/mcp`, which is
offline. Its SHA-256 is
`a91ad29a14d5cf52e0d391e5061d9a84ec0a66d638702373b44e27e5e751a694`.
The original ZIP is retained under the ignored local `dist/superseded/`
archive for provenance; it has been removed from the deployable output path.

## Read-only production check — 2026-11-15 20:01 CST

SSH to `bamn@10.9.66.170` identified `PiInDaSky` (aarch64). `ocliv-relay`
and Caddy were active; live and ready health checks returned `ok`. The
installed relay binary remained `0d47481f2e2b7cbff34df57a713f0e39849be92cd85deabd5f256be07a00d0b1`.
From the Pi, `https://bamnlabs.dynv6.net/v1/agent/challenge` returned HTTP 405
with valid TLS, while the previously known route
`/r/rdZp9IR6xkQKtpu_nLtUEw/mcp` returned 404 with valid TLS. This shows the
edge is answering but that known publication route is unavailable.

The system manager reported `ocliv-publisher.service` and
`ocliv-mcp-publisher.service` as not installed; the user manager reported
`ocliv-mcp-publisher.service` as not installed. `ocliv mcp list` returned 403
both with its stored relay and when directed to
`https://bamnlabs.dynv6.net`; therefore the publication inventory is
**unavailable**, not proven empty. The root-only database inventory was not
read. No production file, service, publication, or database was changed.

No current public endpoint has been qualified. Release packaging is on HOLD
until `scripts/verify-ingress.sh` produces a fresh receipt proving protected
resource metadata, the exact authorization-server issuer, missing and invalid
bearer rejection, authenticated `tools/list`, and successful authenticated
tool execution for the exact URL passed through `OCLIV_QUALIFIED_MCP_URL`.
The release builder rejects the retired host and requires that receipt to be
less than one hour old. ChatGPT registration and off-LAN acceptance remain
separate operator gates.

## Current source status

The Streamable HTTP adapter has per-client sessions and official Go MCP SDK
interoperability tests. `mcp publish --stdio --auth ocliv-managed` is
supported with a required explicit `--name` so restarts reuse the same
identity despite the adapter's ephemeral port. Production route,
external-client, and hosted-assistant qualification remain separate gates.
No public URL is qualified, so no plugin ZIP or ChatGPT endpoint is ready
for use.

## Clean-source staging candidate — 2026-11-15

The review fixes are now committed in source revision
`d9ea67b8578ded3b3af25e296acdd1d7d0e0e126`. Its clean ARM64 candidate has
SHA-256
`7f438b63dd083f34831b133b169707f4d5f479e6aaef7f7894cb4b25e4afc695` and
passed 29/29 isolated Pi staging checks using a fresh database and publisher
identity. The exact command and staging record are in
`PROMOTION-RUNBOOK-2026-11-14.md`.

This qualifies the candidate for production preflight review only. The
production DB schema and publication owner are still unknown because the
root-only read has not completed; the installed production binary remains
`0d47481f…`. No production service, database, credential, or publication was
changed. Public OAuth/tool execution, off-LAN access, and ChatGPT acceptance
remain unverified, so plugin release remains on HOLD.
