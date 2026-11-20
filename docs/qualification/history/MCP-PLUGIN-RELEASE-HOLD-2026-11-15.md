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

## Publisher unit and root-preflight recheck — 2026-11-16

The system manager lists `ocliv-relay.service` as the only Ocliv system
service; it is enabled and active. The user manager has
`ocliv-mcp-publish.service` installed but disabled and inactive.
`ocliv-staging-publish.service` and `ocliv-staging-upstream.service` are also
disabled and inactive, and port 18767 has no listener. Do not enable the
legacy publisher as part of promotion. A publisher should run on the machine
hosting the specifically approved MCP service, under a dedicated production
identity, after the separate publication decision is approved.

The root-only preflight was retried on 2026-11-16. Relay and Caddy remained
active, both health endpoints returned `ok`, and the installed binary hash
remained `0d47481f2e2b7cbff34df57a713f0e39849be92cd85deabd5f256be07a00d0b1`.
The schema-aware SQLite query still could not run because `sudo -n` returned
`sudo: a password is required`. No password was requested or supplied; the
database was not opened.

The connected ChatGPT `OclivMCP` tool was also exercised read-only on
2026-11-16. Its configured MCP URL is the retired Tailscale route
`https://pop-os.tail8d285a.ts.net/r/oadEddDa1TGACd9aW-762w/mcp`; status,
publication-list, and publication-get all failed at connection setup with
`McpServerError: Connection failed`. This identifies why that connected
tool reports the site down: it is still pointed at the old lab edge, not
`bamnlabs.dynv6.net`. This does not establish the production route's database
state or qualify a replacement URL. Do not use direct browser navigation as
an MCP connection test, and do not repoint the connector until a production
route passes the release gates below.

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

## Latest isolated ARM64 candidate — 2026-11-16

The qualified candidate was built from clean source commit
`7674c4b4881b2824f6dc204206f51a46d4ff6ec4`. Its ARM64 SHA-256 is
`e5cd410b52a66641dfdec65d23405f99d21e8978a9e5d49652e507bd61cf63f5`; it
passed 29/29 isolated Pi loopback checks using a fresh database and publisher
identity. The exact source gates also passed: repository-wide Go tests, race
tests for all internal packages, Go vet, and all 86 Skybridge tests. See
`PI-ISOLATED-RESULT-2026-11-16.md`, `pi-staging/PROVENANCE.txt`, and the
updated `PROMOTION-RUNBOOK-2026-11-14.md` for artifact evidence and operator
steps.

This qualifies the candidate for production preflight review only. The
production DB schema and publication owner are still unknown because the
root-only read has not completed; the installed production binary remains
`0d47481f…`. No production service, database, credential, or publication was
changed. Public OAuth/tool execution, off-LAN access, clean-host installation,
24-hour soak, and ChatGPT acceptance remain unverified, so promotion and
plugin release remain on HOLD.
