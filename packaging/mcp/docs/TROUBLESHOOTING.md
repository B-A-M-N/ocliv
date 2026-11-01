# Ocliv MCP runtime — troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `route registration failed` | Relay unreachable / untrusted CA | Check relay is up; for a lab edge set `OCLIV_CACERT` to the lab root (never `-k`) |
| `resource binding NOT verified` then abort (`--strict-discovery`) | Fixture advertises a different resource | Ensure `--resource-file` points at the file the server reads (`MCP_RESOURCE_FILE`) and republish |
| `OAuth discovery unreachable`, publish aborts | Publisher cannot reach the public URL from its network | Expected when the publisher cannot reach the edge; republish where discovery is reachable, or use explicit dev-only `--dev-allow-unverified-discovery` (URL prints NOT VERIFIED, never for ChatGPT) |
| 401 on every call | Wrong/missing token | Compare with the server's `MCP_TOKEN_FILE` content; rotate the file, no restart needed |
| 503 on every call | Lease revoked/expired/closed | `ocliv status`; republish with a fresh TTL |
| `tunnel credential rejected` | Key revoked after `logout`/revoke | Re-enroll with a fresh one-time code |
| `tailscale funnel` hangs | Funnel needs tailnet admin approval | Approve in the admin console, or qualify over the tailnet instead |
| Relay log `421` on `/r/…` | `--mcp-host` mismatch | `--relay-host`/`--mcp-host` must equal the exact public hostname |
| Minted URL missing `:port` | Edge on non-443 without `--mcp-port` | Set `--mcp-port` (or `OCLIV_MCP_PORT`) to the public edge port |

Logs: publisher stderr, fixture stdout (`method=…` lines prove upstream
execution), relay log (admission decisions). `mcp doctor` reports lease,
route, local service, and protocol status separately.
