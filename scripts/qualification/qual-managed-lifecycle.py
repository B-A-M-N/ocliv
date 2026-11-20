"""Priority 5 items 6 and 7: restart, cross-key refusal, and unpublish.

  6. same-key restart (the route id and URL survive a publisher restart)
     and cross-key takeover refusal (a second key is refused, the first
     publisher keeps serving)
  7. unpublish with DURABLE grant retirement: the route's operator
     approvals are retired with the route, in one transaction
"""

import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

RC = os.environ["RC3_DIR"]
BIN = RC + "/bin/ocliv"
DATA = RC + "/data"
DB = DATA + "/ocliv.db"
HOME = RC + "/home"
ROUTE = os.environ["RC_ROUTE_ID"]
MCP_URL = os.environ["RC_MCP_URL"]
BASE = MCP_URL.rsplit("/mcp", 1)[0]

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + ("  " + detail if detail else ""), flush=True)


def db_query(sql, args=()):
    db = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    try:
        return db.execute(sql, args).fetchall()
    finally:
        db.close()


def probe(url):
    req = urllib.request.Request(url, method="POST")
    req.add_header("Content-Type", "application/json")
    req.data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # noqa: BLE001
        return repr(e)


def oc(*args, home=None, timeout=90):
    env = dict(os.environ)
    if home:
        env["HOME"] = home
    p = subprocess.run([BIN] + list(args), env=env, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    # ---- item 6a: same-key restart keeps the route id and URL ----
    before = db_query("SELECT route_id, lease_id FROM mcp_publications WHERE route_id=?", (ROUTE,))
    check("6a the publication exists before the restart", len(before) == 1, "rows=%s" % before)
    route_id_before = before[0][0]

    # Stop the publisher gracefully: the publication is retained offline.
    pid = subprocess.run(["pgrep", "-f", "ocliv mcp publish --local http://127.0.0.1:18999/mcp"],
                         capture_output=True, text=True).stdout.split()
    for p in pid:
        subprocess.run(["kill", "-INT", p], capture_output=True)
    time.sleep(5)
    offline = probe(MCP_URL)
    check("6b after the publisher stops the route is 503 (retained, offline)", offline == 503,
          "status=%s" % offline)
    retained = db_query("SELECT route_id FROM mcp_publications WHERE route_id=?", (ROUTE,))
    check("6c the publication is retained offline", len(retained) == 1, "rows=%s" % retained)

    # Republish under the same key and name: the route id must not change.
    p = subprocess.Popen([BIN, "mcp", "publish", "--local", "http://127.0.0.1:18999/mcp",
                          "--auth", "ocliv-managed", "--name", "rc3"],
                         env={**os.environ, "HOME": HOME},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(14)
    after = db_query("SELECT route_id, lease_id FROM mcp_publications WHERE route_id=?", (ROUTE,))
    check("6d the same-key restart keeps the SAME route id",
          len(after) == 1 and after[0][0] == route_id_before, "rows=%s" % after)
    check("6e the publication moved to a NEW lease",
          len(after) == 1 and after[0][1] != before[0][1],
          "lease %s -> %s" % (before[0][1] if before else None, after[0][1] if after else None))
    online = probe(MCP_URL)
    check("6f the route serves again (401 = alive, auth required)", online == 401, "status=%s" % online)
    check("6g exactly ONE publication row for the name",
          len(db_query("SELECT route_id FROM mcp_publications WHERE pub_name='rc3'")) == 1)

    # ---- item 6h: cross-key takeover refusal ----
    code2, out2 = oc("relay", "issue-enroll", "--data", DATA, "--tenant=rctenant")
    enroll = [l for l in out2.splitlines() if l.startswith("ocliv-enroll-")]
    check("6h a second key can be enrolled in the same tenant", code2 == 0 and len(enroll) == 1)
    if not enroll:
        return 1
    open(RC + "/code2.txt", "w").write(enroll[0])
    os.makedirs(RC + "/home2", exist_ok=True)
    rc2, out = oc("login", "--relay", "https://pop-os.tail8d285a.ts.net",
                  "--code-file", RC + "/code2.txt", home=RC + "/home2")
    check("6i the second key enrolled", rc2 == 0, out.strip()[-120:])
    keys = db_query("SELECT id FROM agent_keys WHERE tenant_id='rctenant'")
    check("6j two keys exist in the tenant", len(keys) == 2, "keys=%s" % keys)

    rc3, out3 = oc("mcp", "publish", "--local", "http://127.0.0.1:18999/mcp",
                   "--auth", "ocliv-managed", "--name", "rc3", home=RC + "/home2", timeout=60)
    check("6k the cross-key takeover is REFUSED with a non-zero exit", rc3 != 0, "exit=%d" % rc3)
    check("6l the refusal is terminal and actionable",
          "held by another agent key" in out3 and "--name" in out3 and "reconnecting" not in out3.lower(),
          "msg=%r" % out3.strip()[-160:])
    owner = db_query("SELECT owner_key_id FROM mcp_publications WHERE route_id=?", (ROUTE,))
    check("6m the original owner still owns the publication",
          len(owner) == 1 and owner[0][0] == keys[0][0], "owner=%s" % owner)
    check("6n the original route still serves", probe(MCP_URL) == 401)
    denied = db_query("SELECT category, result FROM audit_events WHERE result='denied'")
    check("6o the refusal is audited", len(denied) >= 1, "rows=%s" % denied[-3:])

    # ---- item 7: unpublish with durable grant retirement ----
    grants_before = db_query("SELECT client_id, status FROM authz_grants WHERE route_id=?", (ROUTE,))
    check("7a the route has operator grants before unpublish", len(grants_before) >= 1,
          "grants=%s" % grants_before)
    rc4, out4 = oc("mcp", "unpublish", "--name", "rc3", home=HOME, timeout=60)
    check("7b unpublish succeeds", rc4 == 0, "exit=%d %s" % (rc4, out4.strip()[-140:]))
    time.sleep(2)
    pubs = db_query("SELECT route_id FROM mcp_publications WHERE route_id=?", (ROUTE,))
    check("7c the publication is gone", len(pubs) == 0, "rows=%s" % pubs)
    grants_after = db_query("SELECT client_id, status FROM authz_grants WHERE route_id=?", (ROUTE,))
    active = [g for g in grants_after if g[1] != "revoked"]
    check("7d the route's grants were RETIRED with the route", len(active) == 0,
          "grants=%s" % grants_after)
    check("7e the grant rows still exist (durable history, not deleted)",
          len(grants_after) == len(grants_before), "%d -> %d" % (len(grants_before), len(grants_after)))
    clients = db_query("SELECT id FROM authz_clients")
    check("7f client registrations are preserved", len(clients) >= 1, "clients=%s" % clients)
    gone = probe(MCP_URL)
    check("7g the route is 404 after unpublish", gone == 404, "status=%s" % gone)

    print("\n=== RESULT ===")
    failed = [r for r in results if not r[1]]
    print("checks: %d, passed: %d, failed: %d" % (len(results), len(results) - len(failed), len(failed)))
    for name, ok, detail in failed:
        print("  FAILED: %s %s" % (name, detail))
    return 1 if failed else 0


raise SystemExit(main())
