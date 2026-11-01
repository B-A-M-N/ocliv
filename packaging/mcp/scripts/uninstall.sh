#!/bin/sh
# Uninstall Ocliv MCP runtime files installed by hand (not a package
# manager). Stops services first; never touches relay SQLite state or
# operator keys — back those up separately before wiping a host.
set -eu
systemctl stop ocliv-publisher ocliv-mcp-server 2>/dev/null || true
systemctl disable ocliv-publisher ocliv-mcp-server 2>/dev/null || true
rm -f /etc/systemd/system/ocliv-publisher.service \
  /etc/systemd/system/ocliv-mcp-server.service
rm -f /usr/local/bin/ocliv /usr/local/bin/mcp-server
systemctl daemon-reload 2>/dev/null || true
echo "removed binaries and MCP units (relay unit, state, and keys untouched)"
