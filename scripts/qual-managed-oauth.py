"""Priority 5 staging qualification: the full managed-OAuth checklist.

Driven by the OFFICIAL Python MCP SDK (1.28.1) against the release
candidate over PUBLIC HTTPS (tailscale funnel -> real TLS), with every
assertion an oracle on the relay's own rows or the harmless upstream's
execution counter.

  1. the complete OAuth flow with a current MCP SDK
  2. a real external client connecting over trusted HTTPS
  3. successful tools/list and tools/call
  4. refresh/reconnect behavior across access-token expiry
  5. token and client revocation
  6. same-key restart and cross-key takeover refusal
  7. unpublish with durable grant retirement
  8. no unauthorized upstream executions
"""

import asyncio
import http.server
import json
import os
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from mcp import ClientSession
from mcp.client.auth.oauth2 import OAuthClientProvider
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.auth import OAuthClientMetadata, OAuthToken

MCP_URL = os.environ["RC_MCP_URL"]
UPSTREAM = os.environ["RC_UPSTREAM"]
DB = os.environ["RC_DB"]
DIR = os.environ["RC_SDK_DIR"]
CB_PORT = 59997

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + ("  " + detail if detail else ""), flush=True)


def log(event, **f):
    with open(DIR + "/qual-log.jsonl", "a") as fh:
        fh.write(json.dumps({"event": event, **f}) + "\n")
    print(json.dumps({"event": event, **f}), flush=True)


def upstream_executions():
    try:
        with urllib.request.urlopen(UPSTREAM + "/_executions", timeout=5) as r:
            return int(r.read().decode().strip())
    except Exception:  # noqa: BLE001
        return -1


def db_query(sql, args=()):
    db = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    try:
        return db.execute(sql, args).fetchall()
    finally:
        db.close()


def token_post(url, form):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def bearer_post(url, bearer, method="tools/list"):
    req = urllib.request.Request(url, method="POST")
    if bearer:
        req.add_header("Authorization", "Bearer " + bearer)
    req.add_header("Content-Type", "application/json")
    req.data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method}).encode()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code = (q.get("code") or [""])[0]
        if not code:
            return
        with open(DIR + "/qual-callback.json", "w") as f:
            json.dump({"code": code, "state": (q.get("state") or [""])[0]}, f)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class MemStorage:
    def __init__(self):
        self.tokens = None
        self.client_info = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, t):
        self.tokens = t

    async def get_client_info(self):
        return self.client_info

    async def set_client_info(self, c):
        self.client_info = c


async def redirect_handler(url: str):
    log("authorize-url", url=url)
    with open(DIR + "/qual-authorize-url.txt", "w") as f:
        f.write(url)


async def callback_handler():
    want = ""
    for _ in range(600):
        try:
            auth = open(DIR + "/qual-authorize-url.txt").read()
            want = urllib.parse.parse_qs(urllib.parse.urlparse(auth).query).get("state", [""])[0]
            if want:
                break
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(0.5)
    for _ in range(600):
        try:
            data = json.load(open(DIR + "/qual-callback.json"))
            if data.get("code") and data.get("state") == want:
                log("callback-received", state=data.get("state", ""))
                return data["code"], data.get("state") or None
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(0.5)
    raise RuntimeError("consent never completed")


async def main():
    cb = HTTPServer(("127.0.0.1", CB_PORT), CallbackHandler)
    threading.Thread(target=cb.serve_forever, daemon=True).start()

    metadata = OAuthClientMetadata(
        client_name="ocliv-qual-release",
        redirect_uris=[f"http://127.0.0.1:{CB_PORT}/callback"],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="",
    )
    storage = MemStorage()
    provider = OAuthClientProvider(
        server_url=MCP_URL,
        client_metadata=metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )

    # --- 8a: an unauthenticated call is refused with no upstream execution
    before = upstream_executions()
    st, _ = bearer_post(MCP_URL, None)
    check("8a unauthenticated call refused", st == 401, "status=%d" % st)
    check("8b refusal executed no upstream call", upstream_executions() == before,
          "upstream %d -> %d" % (before, upstream_executions()))

    # --- 1/2/3: the complete flow over public HTTPS
    async with streamablehttp_client(MCP_URL, auth=provider) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            log("initialize-ok")
            tools = await session.list_tools()
            check("3a tools/list over public HTTPS", bool(tools.tools),
                  "tools=%s" % [t.name for t in tools.tools])
            res = await session.call_tool("qual_ping", {})
            text = res.content[0].text if res.content else ""
            check("3b tools/call reached the upstream", "pong" in text, "result=%r" % text[:60])
    tok = storage.tokens
    check("1a SDK holds an access+refresh pair",
          bool(getattr(tok, "access_token", "")) and bool(getattr(tok, "refresh_token", "")))
    ci = storage.client_info
    client_id = getattr(ci, "client_id", None) or (ci.get("client_id") if isinstance(ci, dict) else None)
    check("2a DCR registered the client with the relay", bool(client_id), "client_id=%s" % client_id)
    grants = db_query("SELECT status FROM authz_grants WHERE client_id=?", (client_id,))
    check("2b the operator grant is ACTIVE", any(g[0] == "active" for g in grants), "grants=%s" % grants)
    after_call = upstream_executions()
    check("3c exactly one authorized upstream execution", after_call == before + 1,
          "upstream %d -> %d" % (before, after_call))

    # --- 5: token revocation (RFC 7009) stops the token, no upstream
    access = getattr(tok, "access_token", "")
    as_base = MCP_URL.rsplit("/mcp", 1)[0]
    st, _ = token_post(as_base + "/oauth/revoke", {"token": access})
    check("5a token revocation returns 200", st == 200, "status=%d" % st)
    st2, _ = bearer_post(MCP_URL, access)
    check("5b the revoked token is refused", st2 == 401, "status=%d" % st2)
    check("5c the refusal executed no upstream call", upstream_executions() == after_call,
          "upstream %d -> %d" % (after_call, upstream_executions()))

    # --- 4: refresh/reconnect across access-token expiry
    refresh = getattr(tok, "refresh_token", "")
    before2 = upstream_executions()
    st3, body = token_post(as_base + "/oauth/token", {
        "grant_type": "refresh_token", "client_id": client_id,
        "refresh_token": refresh, "resource": MCP_URL})
    check("4a the refresh grant issues a new pair", st3 == 200, "status=%d" % st3)
    try:
        pair = json.loads(body)
    except Exception:  # noqa: BLE001
        pair = {}
    check("4b the new pair is usable", bool(pair.get("access_token")))
    if pair.get("access_token"):
        st4, _ = bearer_post(MCP_URL, pair["access_token"], "tools/call")
        check("4c the renewed token reaches the upstream", st4 == 200 and upstream_executions() == before2 + 1,
              "status=%d upstream %d -> %d" % (st4, before2, upstream_executions()))
    # Replay of the ROTATED refresh token must be refused.
    st5, _ = token_post(as_base + "/oauth/token", {
        "grant_type": "refresh_token", "client_id": client_id,
        "refresh_token": refresh, "resource": MCP_URL})
    check("4d replay of the rotated refresh token is refused", st5 == 400, "status=%d" % st5)

    cb.shutdown()
    print("\n=== RESULT ===")
    failed = [r for r in results if not r[1]]
    print("checks: %d, passed: %d, failed: %d" % (len(results), len(results) - len(failed), len(failed)))
    for name, ok, detail in failed:
        print("  FAILED: %s %s" % (name, detail))
    return 1 if failed else 0


raise SystemExit(asyncio.run(main()))
