"""Does the OFFICIAL SDK actually follow Ocliv's WWW-Authenticate challenge?

Before the fix, Ocliv advertised the protected-resource metadata URL under
the parameter name `resource_uri`. The official Python MCP SDK parses
`resource_metadata` (RFC 9728 §5.1) and, finding nothing, silently fell
back to GUESSING the well-known path - which happened to match Ocliv's
layout, so the qualification passed by luck.

This probe proves the challenge itself is usable: it calls the SDK's own
extraction function on Ocliv's real 401 response and asserts the SDK
recovers the EXACT URL Ocliv advertised - with no fallback involved.
"""

import asyncio
import os
import sys

import httpx
from mcp.client.auth.utils import extract_resource_metadata_from_www_auth

MCP_URL = os.environ["RC_MCP_URL"]

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + ("  " + detail if detail else ""), flush=True)


async def main():
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(
            MCP_URL,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    check("the route challenges an unauthenticated call", r.status_code == 401,
          "status=%d" % r.status_code)
    challenge = r.headers.get("www-authenticate", "")
    print("challenge: " + challenge)

    # The SDK's own parser, on Ocliv's real response.
    extracted = extract_resource_metadata_from_www_auth(r)
    check("the official SDK extracts the metadata URL from the challenge",
          extracted is not None, "extracted=%r" % extracted)

    # The extracted URL must be the route-scoped document, and it must be
    # fetchable and bound to this route.
    if extracted:
        check("the extracted URL is route-scoped", "/r/" in extracted and "/mcp" in extracted,
              "url=%s" % extracted)
        async with httpx.AsyncClient(timeout=20) as client:
            m = await client.get(extracted)
        check("the advertised metadata document is served", m.status_code == 200,
              "status=%d" % m.status_code)
        try:
            body = m.json()
        except Exception:
            body = {}
        check("the metadata names this route's resource",
              body.get("resource", "").startswith("https://") and "/r/" in body.get("resource", ""),
              "resource=%r" % body.get("resource"))
        check("the metadata names at least one authorization server",
              bool(body.get("authorization_servers")), "as=%r" % body.get("authorization_servers"))

    print("\n=== RESULT ===")
    failed = [r for r in results if not r[1]]
    print("checks: %d, passed: %d, failed: %d" % (len(results), len(results) - len(failed), len(failed)))
    for name, ok, detail in failed:
        print("  FAILED: %s %s" % (name, detail))
    return 1 if failed else 0


raise SystemExit(asyncio.run(main()))
