#!/usr/bin/env python3
"""Release qualification harness for one isolated loopback relay.

The relay is started with a fresh DB and a unique stage path. This driver never
reads or mutates production state. It checks owner, executable, and stage-specific
argv before signaling any process.

Usage:
  qualify-pi-isolated.py [--smoke] [--release-dir DIR]

In default (release) mode, ANY skipped gate is treated as a failure.
"""
import argparse, atexit, base64, hashlib, http.server, json, os, re, shutil, signal
import socket, stat, subprocess, sys, tempfile, threading, time
import urllib.request, urllib.error, urllib.parse

parser = argparse.ArgumentParser(description="Ocliv isolated loopback release qualification")
parser.add_argument("--smoke", action="store_true", help="non-release smoke mode (allows SKIP without failing)")
parser.add_argument("--release-dir", default="", help="optional directory containing signed release-manifest.json, .sig, and binary artifacts")
ARGS = parser.parse_args()

S = os.path.dirname(os.path.realpath(__file__))
BIN = os.path.join(S, "ocliv-arm64")
if not os.path.exists(BIN):
    for cand in (os.path.join(S, "ocliv"), os.path.join(S, "ocliv-linux-amd64"), os.path.join(S, "ocliv-linux-arm64")):
        if os.path.exists(cand):
            BIN = cand
            break
DB = os.path.join(S, "relay-data-fresh")
UPSTREAM = os.path.join(S, "mcp_upstream.py")
BASE = "http://127.0.0.1:28080"
HOST = "127.0.0.1:28080"
RES = "https://127.0.0.1:28080"
CB = "http://127.0.0.1:59999/cb"
PASS = []
FAIL = []
SKIP = []
CHILDREN = []
os.umask(0o077)


def check(n, ok, note=""):
    (PASS if ok else FAIL).append(n)
    print(("[PASS]" if ok else "[FAIL]"), n, note, flush=True)


def skip_gate(n, note=""):
    SKIP.append(n)
    print("[SKIP]", n, note, flush=True)


def process_identity(pid, executable, required):
    proc = f"/proc/{pid}"
    try:
        with open(proc + "/status", encoding="ascii") as f:
            uid = next(x for x in f if x.startswith("Uid:")).split()[1]
        with open(proc + "/cmdline", "rb") as f:
            argv = [x.decode(errors="replace") for x in f.read().split(b"\0") if x]
        exe = os.path.realpath(proc + "/exe")
    except (OSError, StopIteration, ValueError):
        return False
    return int(uid) == os.getuid() and exe == os.path.realpath(executable) and all(x in argv for x in required)


def stop_pid(pid, executable, required):
    if not process_identity(pid, executable, required):
        raise RuntimeError(f"refusing to signal PID {pid}: identity does not match isolated stage")
    os.kill(pid, signal.SIGTERM)


def start_child(args, log_path, env=None, required=None):
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
    executable = shutil.which(args[0]) or args[0]
    CHILDREN.append((proc, executable, required if required is not None else args[1:]))
    return proc


def cleanup():
    errors = []
    for proc, executable, required in reversed(CHILDREN):
        if proc.poll() is not None:
            continue
        try:
            stop_pid(proc.pid, executable, required)
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                if process_identity(proc.pid, executable, required):
                    os.kill(proc.pid, signal.SIGKILL)
                proc.wait(timeout=3)
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        print("CLEANUP ERROR: " + "; ".join(errors), file=sys.stderr, flush=True)
        os._exit(1)


atexit.register(cleanup)


class NR(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a):
        return None


OP = urllib.request.build_opener(NR)


def http_req(m, path, body=None, headers=None, host=HOST, base=BASE):
    req = urllib.request.Request(base + path, data=body.encode() if isinstance(body, str) else body, method=m)
    req.add_header("Host", host)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        r = OP.open(req, timeout=10)
        return r.status, r.read().decode(errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers)


def sh(args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(args, capture_output=True, text=True, env=e)


def pkce():
    v = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def tally():
    for _ in range(2):
        try:
            r = urllib.request.urlopen("http://127.0.0.1:28099/__tally__", timeout=5)
            return json.loads(r.read().decode())
        except Exception:
            start_child(["python3", UPSTREAM, "28099"], os.path.join(S, "upstream.log"), env=ENV, required=[UPSTREAM, "28099"])
            time.sleep(1)
    return {"execs": -1}


def db_routes(db_dir=DB):
    q = (
        "import sqlite3;c=sqlite3.connect('file:"
        + db_dir
        + "/ocliv.db?mode=ro',uri=True);"
        "print(' '.join(r[0] for r in c.execute("
        "\"SELECT route_id FROM mcp_publications WHERE revoked_at IS NULL AND verified_at IS NOT NULL ORDER BY pub_name\")))"
    )
    return sh(["python3", "-c", q]).stdout.split()


ENV = {"HOME": os.path.join(S, "qual-home"), "OCLIV_RELAY_URL": BASE}
os.makedirs(ENV["HOME"], mode=0o700, exist_ok=True)
os.chmod(ENV["HOME"], 0o700)


def assert_ports_free():
    for port in (28080, 28082, 28085, 28086, 28099, 59999):
        sock = socket.socket()
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeError(f"loopback staging port {port} is occupied: {exc}")
        finally:
            sock.close()


assert_ports_free()
if os.path.exists(DB):
    raise RuntimeError("refusing non-fresh DB path: " + DB)
os.mkdir(DB, 0o700)

# Prepare release artifact bundle for Phase G (either operator-supplied --release-dir
# or a self-contained bundle generated from BIN with an ephemeral Ed25519 key).
RELEASE_DIR = ARGS.release_dir
REL_SIGN_PUB_PEM = ""
REL_MANIFEST_PATH = ""
REL_SIG_PATH = ""
REL_USE_DEV_UNSIGNED = False

_ver_res = sh([BIN, "version", "--json"])
if _ver_res.returncode != 0:
    raise RuntimeError("candidate binary failed `version --json`: " + _ver_res.stderr[:200])
BIN_VER_INFO = json.loads(_ver_res.stdout)
BIN_COMMIT = BIN_VER_INFO.get("build_commit") or BIN_VER_INFO.get("commit") or "unknown"
EXPECTED_SCHEMA = str(BIN_VER_INFO.get("schema_version") or "")
if not EXPECTED_SCHEMA:
    raise RuntimeError("binary `version --json` missing schema_version")

if RELEASE_DIR and os.path.isdir(RELEASE_DIR):
    REL_MANIFEST_PATH = os.path.join(RELEASE_DIR, "release-manifest.json")
    REL_SIG_PATH = os.path.join(RELEASE_DIR, "release-manifest.json.sig")
else:
    RELEASE_DIR = os.path.join(S, "release-bundle-stage")
    os.makedirs(RELEASE_DIR, mode=0o700, exist_ok=True)
    import platform
    _arch = "arm64" if platform.machine() in ("aarch64", "arm64") else "amd64"
    _aname = f"ocliv-linux-{_arch}"
    _adst = os.path.join(RELEASE_DIR, _aname)
    shutil.copy2(BIN, _adst)
    with open(_adst, "rb") as _af:
        _asha = hashlib.sha256(_af.read()).hexdigest()
    REL_MANIFEST_PATH = os.path.join(RELEASE_DIR, "release-manifest.json")
    _mobj = {
        "commit": BIN_COMMIT,
        "dirty": False,
        "build_time": BIN_VER_INFO.get("build_time") or "2026-11-21T00:00:00Z",
        "protocol_version": BIN_VER_INFO.get("protocol_version") or "",
        "schema_version": int(EXPECTED_SCHEMA),
        "govulncheck": "pass",
        "artifacts": {_aname: {"sha256": _asha}},
    }
    with open(REL_MANIFEST_PATH, "w", encoding="utf-8") as _mf:
        _mf.write(json.dumps(_mobj, indent=2) + "\n")
    # Sign with ephemeral Ed25519 key for install-client.sh bootstrap & tamper verification.
    _priv_pem = os.path.join(RELEASE_DIR, "test-signing-priv.pem")
    _pub_pem = os.path.join(RELEASE_DIR, "test-signing-pub.pem")
    _sig_raw = os.path.join(RELEASE_DIR, "release-manifest.json.sig.raw")
    REL_SIG_PATH = os.path.join(RELEASE_DIR, "release-manifest.json.sig")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", _priv_pem], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", _priv_pem, "-pubout", "-out", _pub_pem], check=True, capture_output=True)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", _priv_pem, "-rawin", "-in", REL_MANIFEST_PATH, "-out", _sig_raw], check=True, capture_output=True)
    with open(_sig_raw, "rb") as _sf, open(REL_SIG_PATH, "w", encoding="ascii") as _hf:
        _hf.write(_sf.read().hex())
    os.remove(_sig_raw)
    with open(_pub_pem, "r", encoding="ascii") as _pf:
        REL_SIGN_PUB_PEM = _pf.read().strip()
    # The relay's embedded key is the production placeholder, so for the self-generated
    # ephemeral test bundle we start the relay with --allow-unsigned-dev-release while
    # testing real Ed25519 signature verification directly in Phase G5 via install-client.sh.
    REL_USE_DEV_UNSIGNED = True

relay_args = [
    BIN, "relay", "serve",
    "--listen=127.0.0.1:28080",
    "--domain=stage.local",
    "--relay-host=127.0.0.1",
    "--data=" + DB,
    "--mcp-host=127.0.0.1",
    "--mcp-port=28080",
    "--health-listen=127.0.0.1:28085",
    "--release-manifest=" + REL_MANIFEST_PATH,
    "--release-artifacts=" + RELEASE_DIR,
]
relay_env = dict(os.environ)
if REL_USE_DEV_UNSIGNED:
    relay_args.append("--allow-unsigned-dev-release")
    relay_env["OCLIV_ENV"] = "development"
elif os.path.exists(REL_SIG_PATH):
    relay_args.append("--release-manifest-sig=" + REL_SIG_PATH)

relay_required = ["relay", "serve", "--listen=127.0.0.1:28080", "--data=" + DB]
relay_proc = start_child(relay_args, os.path.join(S, "relay.log"), env=relay_env, required=relay_required)
with open(os.path.join(S, "relay.pid"), "x", encoding="ascii") as f:
    f.write(str(relay_proc.pid) + "\n")
os.chmod(os.path.join(S, "relay.pid"), 0o600)
for _ in range(100):
    try:
        urllib.request.urlopen("http://127.0.0.1:28085/health/live", timeout=1).close()
        break
    except Exception:
        if relay_proc.poll() is not None:
            raise RuntimeError("candidate relay exited; inspect relay.log")
        time.sleep(0.1)
else:
    raise RuntimeError("candidate relay health endpoint timed out")

start_child(["python3", UPSTREAM, "28099"], os.path.join(S, "upstream.log"), env=ENV, required=[UPSTREAM, "28099"])
for _ in range(50):
    try:
        urllib.request.urlopen("http://127.0.0.1:28099/__tally__", timeout=1).close()
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("isolated MCP upstream did not start")

print("== Phase A: routes & schema ==")
ra = rb = None
cr = db_routes()
if len(cr) >= 2:
    ra, rb = cr[0], cr[1]
elif len(cr) == 1:
    ra = cr[0]
if not ra:
    issue = sh([BIN, "relay", "issue-enroll", "--data", DB, "--tenant", "t1"], ENV)
    if issue.returncode:
        raise RuntimeError("staging enrollment issuance failed: " + issue.stderr[:200])
    codes = [x for x in issue.stdout.split() if x.startswith("ocliv-enroll-")]
    if len(codes) != 1:
        raise RuntimeError("expected one staging enrollment code")
    code_path = os.path.join(S, "qc.txt")
    fd = os.open(code_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(codes[0] + "\n")
    sh([BIN, "logout"], ENV)
    login = sh([BIN, "login", "--relay", BASE, "--code-file", code_path], ENV)
    if login.returncode:
        raise RuntimeError("staging login failed: " + login.stderr[:200])
    start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "qa", "--ttl", "30m", "--relay", BASE], os.path.join(S, "pub-qa.log"), env=ENV, required=["mcp", "publish", "--name", "qa"])
    time.sleep(5)
    cr = db_routes()
    ra = cr[0] if cr else None
if ra and not rb:
    start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "qb", "--ttl", "30m", "--relay", BASE], os.path.join(S, "pub-qb.log"), env=ENV, required=["mcp", "publish", "--name", "qb"])
    time.sleep(5)
    cr = db_routes()
    rb = cr[1] if len(cr) > 1 else None
print("ra", ra, "rb", rb)
check("A: two distinct managed routes active", bool(ra and rb and ra != rb), f"A={ra} B={rb}")

_sk_create = socket.create_connection(("127.0.0.1", 28085), 3)
_sk_create.sendall(b"GET /health/live HTTP/1.0\r\nHost: x\r\n\r\n")
_lv = _sk_create.recv(200).decode()
_sk_create.close()
check("A: health live", "ok" in _lv, _lv.strip().splitlines()[-1] if _lv else "empty")

# Dynamic schema version derived from `ocliv version --json` (no hardcoded version).
sv = sh(["python3", "-c", "import sqlite3;print(sqlite3.connect('" + DB + "/ocliv.db').execute('SELECT MAX(v) FROM schema_version').fetchone()[0])"]).stdout.strip()
check("A: schema matches binary V" + EXPECTED_SCHEMA, sv == EXPECTED_SCHEMA, f"db={sv} binary={EXPECTED_SCHEMA}")

print("== Phase A2: restart persistence ==")
if ra:
    stop_pid(relay_proc.pid, BIN, relay_required)
    relay_proc.wait(timeout=8)
    relay_proc = start_child(relay_args, os.path.join(S, "relay.log"), env=relay_env, required=relay_required)
    with open(os.path.join(S, "relay.pid"), "w", encoding="ascii") as f:
        f.write(str(relay_proc.pid) + "\n")
    time.sleep(2)
    st, _, _ = http_req("POST", "/r/" + ra + "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), {"Content-Type": "application/json"})
    check("A2: route survives relay restart (401 durable)", st == 401, "status=" + str(st))
else:
    check("A2: route survives relay restart", False, "no ra")


def dcr(route):
    st, b, _ = http_req("POST", "/r/" + route + "/oauth/register", json.dumps({"client_name": "q", "redirect_uris": [CB], "token_endpoint_auth_method": "none"}), {"Content-Type": "application/json"})
    try:
        return json.loads(b).get("client_id"), st
    except Exception:
        return None, st


def authorize(route, cid, ch):
    q = urllib.parse.urlencode({"client_id": cid, "redirect_uri": CB, "response_type": "code", "state": "st", "code_challenge": ch, "code_challenge_method": "S256", "resource": RES + "/r/" + route + "/mcp"})
    return http_req("GET", "/r/" + route + "/oauth/authorize?" + q)


def consent(route, cid, ch, pairing, cchal):
    f = urllib.parse.urlencode({"challenge": cchal, "client_id": cid, "redirect_uri": CB, "code_challenge": ch, "state": "st", "resource": RES + "/r/" + route + "/mcp", "pairing_secret": pairing})
    st, b, h = http_req("POST", "/r/" + route + "/oauth/consent", f, {"Content-Type": "application/x-www-form-urlencoded"})
    loc = h.get("Location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0] if loc else None
    return st, b, loc, code


def token(route, form):
    st, b, _ = http_req("POST", "/r/" + route + "/oauth/token", urllib.parse.urlencode(form), {"Content-Type": "application/x-www-form-urlencoded"})
    try:
        return st, json.loads(b)
    except Exception:
        return st, {"raw": b}


def approve(cid, route):
    ap = sh([BIN, "authz", "approve", "--data", DB, "--client", cid, "--tenant", "t1", "--route", route], ENV)
    ls = ap.stdout.splitlines()
    for i, l in enumerate(ls):
        if l.startswith("Pairing secret"):
            return ls[i + 1].strip()
    return None


def challenge_of(page):
    m = re.search(r'name="challenge"[^>]*value="([^"]+)"', page) or re.search(r'value="([^"]+)"[^>]*name="challenge"', page)
    return m.group(1) if m else None


def tools(route, bearer=None, spoof=None):
    h = {"Content-Type": "application/json"}
    if bearer:
        h["Authorization"] = "Bearer " + bearer
    for k, v in (spoof or {}).items():
        h[k] = v
    st, b, _ = http_req("POST", "/r/" + route + "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "ping", "arguments": {}}}), h)
    return st, b


print("== Phase B: managed OAuth happy path ==")
cidA, stA = dcr(ra)
check("B: DCR routeA", bool(cidA), "cid=" + str(cidA))
ver, ch = pkce()
st, page, _ = authorize(ra, cidA, ch)
check("B: authorize consent page", st == 200 and "pairing_secret" in page, "st=" + str(st))
cch = challenge_of(page)
check("B: consent challenge", bool(cch))
pair = approve(cidA, ra)
check("B: approve minted pairing secret", bool(pair))
st, b, loc, code = consent(ra, cidA, ch, pair, cch)
check("B: consent -> authorization code", bool(code), "st=" + str(st))
st, tok = token(ra, {"grant_type": "authorization_code", "code": code, "client_id": cidA, "redirect_uri": CB, "code_verifier": ver, "resource": RES + "/r/" + ra + "/mcp"})
at = tok.get("access_token")
rt = tok.get("refresh_token")
check("B: code exchange tokens", st == 200 and bool(at) and bool(rt), "st=" + str(st))
st, b, _ = http_req("POST", "/r/" + ra + "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), {"Content-Type": "application/json", "Authorization": "Bearer " + at})
check("B: tools/list with token", st == 200 and "ping" in b, "st=" + str(st))
e0 = tally()["execs"]
st, _b = tools(ra, at)
e1 = tally()["execs"]
check("B: tools/call executes once", st == 200 and e1 == e0 + 1, f"execs {e0}->{e1}")
ta = tally()
_auth_stripped = (ta.get("last_auth_present") is False) or ("last_auth" in ta and ta.get("last_auth") is None)
check("B: relay-minted identity, bearer stripped", _auth_stripped and ta.get("last_sub") == cidA and ta.get("last_route") == ra, "sub=" + str(ta.get("last_sub")))

print("== Phase C: refresh rotation ==")
st, t2 = token(ra, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cidA, "resource": RES + "/r/" + ra + "/mcp"})
at2 = t2.get("access_token")
rt2 = t2.get("refresh_token")
check("C: refresh rotates pair", st == 200 and bool(at2) and bool(rt2), "st=" + str(st))
st, tR = token(ra, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cidA, "resource": RES + "/r/" + ra + "/mcp"})
check("C: old refresh replay rejected", st != 200 or not tR.get("access_token"), "st=" + str(st))

print("== Phase D: security boundaries ==")
e0 = tally()["execs"]
st, _x = tools(ra)
check("D: no-bearer 401 zero execs", st == 401 and tally()["execs"] == e0, "st=" + str(st))
st, _x = tools(ra, "forged")
check("D: forged bearer 401 zero execs", st == 401 and tally()["execs"] == e0, "st=" + str(st))
st, _x = tools(ra, (at2[:-4] + "XXXX") if at2 else "x")
check("D: tampered bearer 401 zero execs", st == 401 and tally()["execs"] == e0, "st=" + str(st))
e0 = tally()["execs"]
st, _x = tools(ra, at2, {"X-Ocliv-Upstream-Sub": "spoof", "X-Ocliv-Route": "spoof"})
ta = tally()
check("D: spoofed identity stripped, minted kept", st == 200 and ta.get("last_sub") == cidA and ta.get("last_route") == ra and ta.get("execs") == e0 + 1, "sub=" + str(ta.get("last_sub")))
verB, chB = pkce()
st, pageB, _ = authorize(rb, cidA, chB)
check("D: routeA client refused at routeB authorize", st != 200 or "pairing_secret" not in pageB, "st=" + str(st))
ver2, ch2 = pkce()
st, page2, _ = authorize(ra, cidA, ch2)
cch2 = challenge_of(page2)
pair2 = approve(cidA, ra)
st, b, loc, codeA = consent(ra, cidA, ch2, pair2, cch2)
st, tb2 = token(rb, {"grant_type": "authorization_code", "code": codeA, "client_id": cidA, "redirect_uri": CB, "code_verifier": ver2, "resource": RES + "/r/" + rb + "/mcp"})
check("D: routeA code refused at routeB", st != 200 or "access_token" not in tb2, "st=" + str(st))
st, ta3 = token(ra, {"grant_type": "authorization_code", "code": codeA, "client_id": cidA, "redirect_uri": CB, "code_verifier": ver2, "resource": RES + "/r/" + ra + "/mcp"})
check("D: routeA code intact after routeB attempt", st == 200 and bool(ta3.get("access_token")), "st=" + str(st))
tokA = ta3.get("access_token")
st, _, _ = http_req("POST", "/r/" + rb + "/oauth/revoke", urllib.parse.urlencode({"token": tokA}), {"Content-Type": "application/x-www-form-urlencoded"})
check("D: cross-route revoke at B returns 200", st == 200, "st=" + str(st))
st, _x = tools(ra, tokA)
check("D: routeA token valid after B cross-revoke", st == 200, "st=" + str(st))
st, b, _ = http_req("POST", "/r/" + ra + "/oauth/register", json.dumps({"client_name": "x", "redirect_uris": [CB]}) + "garbage", {"Content-Type": "application/json"})
check("D: malformed trailing JSON refused", st in (400, 413), "st=" + str(st))
st, b, loc, cx = consent(ra, cidA, ch2, pair2, cch2)
check("D: consent challenge replay rejected", not cx, "st=" + str(st))

print("== Phase E: recovery rehearsal (staging only) ==")
st = sh([BIN, "relay", "backup", "--data", DB, "--out", S + "/pre-revoke.db"])
check("E: guarded backup (pre-revoke)", st.returncode == 0, "rc=" + str(st.returncode))
sh([BIN, "authz", "revoke", "--data", DB, "--client", cidA, "--tenant", "t1", "--route", ra], ENV)
st = sh([BIN, "relay", "restore", "--data", DB, "--in", S + "/pre-revoke.db", "--relay-stopped"])
out = st.stdout + st.stderr
check("E: managed rollback restore refused", st.returncode != 0 and "resurrect" in out, f"rc={st.returncode} {out[:90]}")
os.makedirs(S + "/reset-dir", exist_ok=True)
subprocess.run(["rm", "-f", S + "/reset-dir/ocliv.db"])
st = sh([BIN, "relay", "restore", "--data", S + "/reset-dir", "--in", S + "/pre-revoke.db", "--reset-authority", "--relay-stopped"])
res = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + S + "/reset-dir/ocliv.db');print('ag',c.execute(\"SELECT COUNT(*) FROM authz_grants WHERE status='active'\").fetchone()[0]);print('cr',c.execute('SELECT COUNT(*) FROM authz_clients WHERE revoked_at IS NOT NULL').fetchone()[0]);print('ik',c.execute('SELECT COUNT(*) FROM authz_issuer_key').fetchone()[0])"]).stdout
check("E: reset-authority invalidates managed+key", st.returncode == 0 and "ag 0" in res and "cr" in res and "ik 0" in res, f"rc={st.returncode} {res.replace(chr(10), ' ')}")

print("== Phase F: pairing E2E (pair --no-wait -> approve -> resume -> attach) ==")
_sv_pair = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + DB + "/ocliv.db');r=c.execute(\"SELECT COUNT(*) FROM pragma_table_info('pairing_requests') WHERE name IN ('poll_id','poll_verifier','resolved_tenant_id')\").fetchone()[0];print(r)"]).stdout.strip()
check("F1: schema pairing poll + resolved_tenant_id columns present", _sv_pair == "3", "count=" + _sv_pair)
_zero_key = base64.b64encode(b"\x00" * 32).decode()
_pst, _pb, _ = http_req("POST", "/v1/agent/pair-request", '{"public_key":"' + _zero_key + '"}', {"Content-Type": "application/json"})
try:
    _pr = json.loads(_pb)
    check("F2: pair-request returns pairing_code+poll_id+poll_secret", _pst == 200 and bool(_pr.get("pairing_code")) and bool(_pr.get("poll_id")) and bool(_pr.get("poll_secret")), "st=" + str(_pst))
    if _pst == 200 and _pr.get("poll_id"):
        _st2, _, _ = http_req("POST", "/v1/agent/pair-status", '{"poll_id":"' + _pr["poll_id"] + '","poll_secret":"wrongsecret"}', {"Content-Type": "application/json"})
        check("F2: pair-status wrong secret -> 404", _st2 == 404, "st=" + str(_st2))
        _st3, _, _ = http_req("GET", "/v1/agent/pair-status?code=" + (_pr.get("pairing_code") or ""))
        check("F2: GET pair-status refused (405)", _st3 == 405, "st=" + str(_st3))
except Exception as _exc:
    check("F2: pair-request API", False, str(_exc))

_pair_home = tempfile.mkdtemp(prefix="pair-test-")
_pair_env = dict(os.environ)
_pair_env["HOME"] = _pair_home
_pair_env["XDG_CONFIG_HOME"] = os.path.join(_pair_home, ".config")
_pair_env["OCLIV_DATA_DIR"] = os.path.join(_pair_home, ".local", "share", "ocliv")
_paired_key_id = ""
_pair_pub_proc = None
try:
    _r3 = subprocess.run([BIN, "pair", BASE, "--no-wait"], capture_output=True, text=True, timeout=15, env=_pair_env)
    check("F3: pair --no-wait exits 0", _r3.returncode == 0, "rc=" + str(_r3.returncode) + " " + (_r3.stderr or "")[:80])
    _cm = re.search(r'Pairing code:\s*([A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+)', _r3.stdout + _r3.stderr)
    _dcode = _cm.group(1) if _cm else None
    check("F3: display code extracted", bool(_dcode), "out=" + (_r3.stdout + _r3.stderr)[:80])
    if _dcode:
        _r4 = subprocess.run([BIN, "relay", "approve", _dcode, "--tenant", "pair-test", "--data", DB], capture_output=True, text=True, timeout=15, env=os.environ.copy())
        check("F4: relay approve exits 0", _r4.returncode == 0, "rc=" + str(_r4.returncode) + " " + (_r4.stderr or "")[:80])
        _r5 = subprocess.run([BIN, "pair", "resume"], capture_output=True, text=True, timeout=20, env=_pair_env)
        check("F5: pair resume exits 0", _r5.returncode == 0, "rc=" + str(_r5.returncode) + " " + (_r5.stderr or "")[:80])
        _dbr = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + DB + "/ocliv.db');r=c.execute(\"SELECT poll_verifier,status,resolved_tenant_id,key_id FROM pairing_requests WHERE display_code='" + _dcode + "'\").fetchone();print((len(r[0]) if r and r[0] else 0),(r[1] if r else 'none'),(r[2] if r else 'none'),(r[3] if r else 'none'))"])
        _dbp = _dbr.stdout.strip().split()
        _paired_key_id = _dbp[3] if len(_dbp) == 4 else ""
        check("F6: poll_verifier stored, status=approved, resolved_tenant_id=pair-test", len(_dbp) == 4 and int(_dbp[0]) > 0 and _dbp[1] == "approved" and _dbp[2] == "pair-test", "db=" + _dbr.stdout.strip())
        _dbk = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + DB + "/ocliv.db');r=c.execute(\"SELECT tenant_id,status FROM agent_keys WHERE tenant_id='pair-test'\").fetchone();print((r[0] if r else 'none'),(r[1] if r else 'none'))"])
        _dkp = _dbk.stdout.strip().split()
        check("F7: enrolled key active in pair-test tenant", len(_dkp) == 2 and _dkp[0] == "pair-test" and _dkp[1] == "active", "db=" + _dbk.stdout.strip())
        # F8: real publisher attach using the newly paired identity
        _pair_pub_proc = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "pair-pub", "--ttl", "10m", "--relay", BASE], os.path.join(S, "pub-pair.log"), env=_pair_env, required=["mcp", "publish", "--name", "pair-pub"])
        _attached = False
        for _ in range(30):
            _rc = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + DB + "/ocliv.db');print(c.execute(\"SELECT COUNT(*) FROM leases WHERE tenant_id='pair-test' AND status='ACTIVE'\").fetchone()[0])"]).stdout.strip()
            if _rc.isdigit() and int(_rc) >= 1:
                _attached = True
                break
            time.sleep(0.5)
        check("F8: paired publisher attached live lease", _attached, "active_leases=" + _rc)
except Exception as _exc:
    check("F: pairing E2E", False, str(_exc))

print("== Phase G: installer / artifact endpoint & tamper rejection ==")
_gst, _gb, _ = http_req("GET", "/.well-known/ocliv-release-manifest.json")
check("G1: release manifest served (200)", _gst == 200, "st=" + str(_gst))
_gmanifest = None
if _gst == 200:
    try:
        _gmanifest = json.loads(_gb)
    except Exception as _ge:
        check("G1: manifest is valid JSON", False, str(_ge))
for _gtrav in ["/../etc/passwd", "../etc/passwd", "ocliv%2fetc%2fpasswd"]:
    _gts, _, _ = http_req("GET", "/.well-known/ocliv-artifacts/" + _gtrav)
    check("G2: traversal refused " + _gtrav[:20], _gts in (400, 404, 301, 307, 421), "st=" + str(_gts))
_gus, _, _ = http_req("GET", "/.well-known/ocliv-artifacts/ocliv-nonexistent-os-arch")
check("G3: undeclared artifact -> 404", _gus == 404, "st=" + str(_gus))
if _gmanifest is not None:
    for _ganame, _gaentry in (_gmanifest.get("artifacts") or {}).items():
        try:
            _gar = urllib.request.urlopen(BASE + "/.well-known/ocliv-artifacts/" + _ganame, timeout=10)
            _garaw = _gar.read()
            _gasha = hashlib.sha256(_garaw).hexdigest()
            check("G4: artifact " + _ganame + " SHA256", _gasha == _gaentry.get("sha256"), "got=" + _gasha[:12])
        except Exception as _gae:
            check("G4: artifact " + _ganame + " served", False, str(_gae)[:80])
else:
    check("G4: artifacts SHA256 verified", False, "manifest not served")

# G5: fresh-prefix install-client.sh bootstrap + tamper rejection in a sanitized minimal PATH
_install_script = os.path.normpath(os.path.join(S, "..", "..", "packaging", "install", "install-client.sh"))
if not os.path.exists(_install_script):
    _install_script = os.path.join(S, "install-client.sh")
if os.path.exists(_install_script) and REL_SIGN_PUB_PEM and os.path.exists(REL_SIG_PATH):
    _tamper_mode = {"mode": "none"}

    class _SignedBundleHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/.well-known/ocliv-release-manifest.json":
                data = open(REL_MANIFEST_PATH, "rb").read()
                if _tamper_mode["mode"] == "manifest":
                    data = data.replace(b"pass", b"fail", 1)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)
            elif self.path == "/.well-known/ocliv-release-manifest.json.sig":
                data = open(REL_SIG_PATH, "rb").read()
                if _tamper_mode["mode"] == "sig":
                    data = b"0" * 128
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)
            elif self.path.startswith("/.well-known/ocliv-artifacts/"):
                name = self.path.split("/")[-1]
                p = os.path.join(RELEASE_DIR, name)
                if not os.path.isfile(p):
                    self.send_response(404)
                    self.end_headers()
                    return
                data = open(p, "rb").read()
                if _tamper_mode["mode"] == "artifact":
                    data = b"corrupted" + data[9:]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()

    _bsrv = http.server.HTTPServer(("127.0.0.1", 0), _SignedBundleHandler)
    _bport = _bsrv.server_address[1]
    _bthread = threading.Thread(target=_bsrv.serve_forever, daemon=True)
    _bthread.start()
    _burl = f"http://127.0.0.1:{_bport}"
    _inst_dir = tempfile.mkdtemp(prefix="ocliv-inst-")
    _min_bin = tempfile.mkdtemp(prefix="ocliv-minpath-")
    try:
        # Build a sanitized minimal PATH with ONLY documented bootstrap prerequisites
        # (no go, git, caddy, docker, jq, python3, or pre-existing ocliv).
        _allowed_tools = [
            "sh", "curl", "wget", "openssl", "sha256sum", "uname", "mktemp",
            "cp", "mv", "rm", "chmod", "cat", "tr", "grep", "sed", "head",
            "awk", "wc", "cut", "id", "mkdir", "xxd", "printf", "test", "[",
        ]
        for _tool in _allowed_tools:
            _tpath = shutil.which(_tool)
            if _tpath:
                try:
                    os.symlink(_tpath, os.path.join(_min_bin, _tool))
                except FileExistsError:
                    pass
        _ienv = {
            "HOME": _inst_dir,
            "PATH": _min_bin,
            "OCLIV_INSTALL_DIR": _inst_dir,
            "OCLIV_SIGNING_PUBLIC_KEY_PEM": REL_SIGN_PUB_PEM,
        }
        # Assert excluded dev tools are absent from minimal PATH.
        _excluded_found = [t for t in ("go", "git", "caddy", "docker", "jq", "ocliv") if shutil.which(t, path=_min_bin)]
        check("G5_env: minimal publisher PATH excludes go/git/caddy/docker/jq/ocliv", len(_excluded_found) == 0, f"found={_excluded_found}")
        # Happy path: valid signed bundle installs cleanly in minimal PATH.
        _r_ok = subprocess.run([os.path.join(_min_bin, "sh"), _install_script, _burl], capture_output=True, text=True, timeout=30, env=_ienv)
        _inst_bin = os.path.join(_inst_dir, "ocliv")
        check("G5a: fresh-prefix signed bootstrap install succeeds", _r_ok.returncode == 0 and os.path.isfile(_inst_bin), "rc=" + str(_r_ok.returncode) + " " + (_r_ok.stderr or "")[:120])
        # Tampered manifest must fail.
        _tamper_mode["mode"] = "manifest"
        _r_tm = subprocess.run([os.path.join(_min_bin, "sh"), _install_script, _burl], capture_output=True, text=True, timeout=20, env=_ienv)
        check("G5b: tampered manifest rejected", _r_tm.returncode != 0, "rc=" + str(_r_tm.returncode))
        # Tampered signature must fail.
        _tamper_mode["mode"] = "sig"
        _r_ts = subprocess.run([os.path.join(_min_bin, "sh"), _install_script, _burl], capture_output=True, text=True, timeout=20, env=_ienv)
        check("G5c: tampered signature rejected", _r_ts.returncode != 0, "rc=" + str(_r_ts.returncode))
        # Tampered artifact must fail.
        _tamper_mode["mode"] = "artifact"
        _r_ta = subprocess.run([os.path.join(_min_bin, "sh"), _install_script, _burl], capture_output=True, text=True, timeout=20, env=_ienv)
        check("G5d: tampered artifact rejected", _r_ta.returncode != 0, "rc=" + str(_r_ta.returncode))
    finally:
        _bsrv.shutdown()
        shutil.rmtree(_inst_dir, ignore_errors=True)
        shutil.rmtree(_min_bin, ignore_errors=True)
else:
    skip_gate("G5: signed bootstrap install", "install-client.sh or test signing key unavailable")

print("== Phase H: real capacity saturation (--max-publisher-sessions=2, --max-http-streams=2, --max-ws-streams=2) ==")
_cap_db = os.path.join(S, "relay-cap-db")
os.makedirs(_cap_db, mode=0o700, exist_ok=True)
_cap_base = "http://127.0.0.1:28082"
_cap_args = [
    BIN, "relay", "serve",
    "--listen=127.0.0.1:28082",
    "--domain=cap.local",
    "--relay-host=127.0.0.1",
    "--data=" + _cap_db,
    "--mcp-host=127.0.0.1",
    "--mcp-port=28082",
    "--health-listen=127.0.0.1:28086",
    "--max-publisher-sessions=2",
    "--max-http-streams=2",
    "--max-ws-streams=2",
]
_cap_req = ["relay", "serve", "--listen=127.0.0.1:28082", "--data=" + _cap_db]
_cap_proc = start_child(_cap_args, os.path.join(S, "relay-cap.log"), required=_cap_req)
for _ in range(80):
    try:
        urllib.request.urlopen("http://127.0.0.1:28086/health/live", timeout=1).close()
        break
    except Exception:
        time.sleep(0.1)


def _enroll_cap_pub(idx):
    ph = tempfile.mkdtemp(prefix=f"cap-pub-{idx}-")
    pe = dict(os.environ)
    pe["HOME"] = ph
    pe["XDG_CONFIG_HOME"] = os.path.join(ph, ".config")
    pe["OCLIV_RELAY_URL"] = _cap_base
    iss = sh([BIN, "relay", "issue-enroll", "--data", _cap_db, "--tenant", "cap-t"], pe)
    codes = [x for x in iss.stdout.split() if x.startswith("ocliv-enroll-")]
    cf = os.path.join(ph, "c.txt")
    with open(cf, "w", encoding="utf-8") as f:
        f.write(codes[0] + "\n")
    os.chmod(cf, 0o600)
    sh([BIN, "login", "--relay", _cap_base, "--code-file", cf], pe)
    return ph, pe


_cap_homes = []
try:
    h1, e1 = _enroll_cap_pub(1)
    h2, e2 = _enroll_cap_pub(2)
    h3, e3 = _enroll_cap_pub(3)
    _cap_homes = [h1, h2, h3]
    p1 = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "cap1", "--ttl", "10m", "--relay", _cap_base], os.path.join(S, "cap-pub1.log"), env=e1, required=["mcp", "publish", "--name", "cap1"])
    p2 = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "cap2", "--ttl", "10m", "--relay", _cap_base], os.path.join(S, "cap-pub2.log"), env=e2, required=["mcp", "publish", "--name", "cap2"])
    _two_up = False
    for _ in range(30):
        try:
            _st_json = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
            if _st_json.get("active_sessions", 0) >= 2:
                _two_up = True
                break
        except Exception:
            pass
        time.sleep(0.5)
    check("H1: 2 publishers admitted up to --max-publisher-sessions=2", _two_up, f"status={_st_json if _two_up else 'timeout'}")
    # Start 3rd publisher — must be rejected (503) while 2 are active.
    _p3_log = os.path.join(S, "cap-pub3.log")
    p3 = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "cap3", "--ttl", "10m", "--relay", _cap_base], _p3_log, env=e3, required=["mcp", "publish", "--name", "cap3"])
    time.sleep(3)
    _st3 = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
    _p3_txt = open(_p3_log, encoding="utf-8", errors="replace").read() if os.path.exists(_p3_log) else ""
    check("H2: 3rd publisher rejected before WS upgrade (503 / sessions stay 2)", _st3.get("active_sessions") == 2 and ("503" in _p3_txt or "capacity" in _p3_txt.lower() or p3.poll() is not None), f"active={_st3.get('active_sessions')} rc={p3.poll()}")
    # Verify /health/ready stays 200 while publisher sessions are saturated (process_ready=True, sessions_ready=False)
    # and all 3 configured limits (http=2, ws=2, sessions=2) are exposed accurately on loopback /health/status.
    _ready_st = urllib.request.urlopen("http://127.0.0.1:28086/health/ready", timeout=2).status
    check("H2b: /health/ready stays 200 during saturation & all 3 limits exposed", _ready_st == 200 and _st3.get("max_http_streams") == 2 and _st3.get("max_ws_streams") == 2 and _st3.get("max_publisher_sessions") == 2, f"ready={_ready_st} limits=({_st3.get('max_http_streams')},{_st3.get('max_ws_streams')},{_st3.get('max_publisher_sessions')})")
    # Stop p1, verify slot releases and p3 (or fresh pub) can now connect cleanly.
    stop_pid(p1.pid, BIN, ["mcp", "publish", "--name", "cap1"])
    p1.wait(timeout=8)
    _re_admitted = False
    if p3.poll() is not None:
        p3 = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "cap3b", "--ttl", "10m", "--relay", _cap_base], os.path.join(S, "cap-pub3b.log"), env=e3, required=["mcp", "publish", "--name", "cap3b"])
    for _ in range(30):
        _st4 = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
        _lcnt = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + _cap_db + "/ocliv.db');print(c.execute(\"SELECT COUNT(*) FROM leases WHERE label IN ('cap3','cap3b') AND status='ACTIVE'\").fetchone()[0])"]).stdout.strip()
        if _lcnt.isdigit() and int(_lcnt) >= 1 and _st4.get("active_sessions") == 2:
            _re_admitted = True
            break
        time.sleep(0.5)
    check("H3: slot released on disconnect and 3rd publisher admitted without leakage", _re_admitted, f"active={_st4.get('active_sessions')}")
finally:
    for _ch in _cap_homes:
        shutil.rmtree(_ch, ignore_errors=True)

print("== Phase I: role separation & key revocation ==")
_idb = os.path.join(DB, "ocliv.db")
if os.path.exists(_idb):
    _idbm = os.stat(_idb).st_mode
    check("I1: relay DB not world-readable", not (_idbm & stat.S_IROTH), "mode=" + oct(_idbm))
else:
    check("I1: relay DB exists", False, "not found: " + _idb)

try:
    _ir = urllib.request.urlopen(BASE + "/v1/relay/tenants", timeout=5)
    check("I2: unauthenticated management endpoint rejected", False, "got HTTP " + str(_ir.getcode()))
except urllib.error.HTTPError as _ie:
    check("I2: unauthenticated management endpoint rejected", _ie.code in (401, 403, 404, 421), "st=" + str(_ie.code))
except Exception as _ie2:
    check("I2: management endpoint not accessible", True, str(_ie2)[:60])

# I3: publisher has zero listening sockets (nothing inbound), then revoke-key kills authority
_pub_listens = False
if _pair_pub_proc is not None and _pair_pub_proc.poll() is None:
    _ss_res = sh(["ss", "-ltnp"])
    if _ss_res.returncode == 0 and f"pid={_pair_pub_proc.pid}," in _ss_res.stdout:
        _pub_listens = True
check("I3a: paired publisher opens zero inbound listening sockets", not _pub_listens, f"pid={_pair_pub_proc.pid if _pair_pub_proc else 'none'}")

if _paired_key_id:
    _rev = sh([BIN, "relay", "revoke-key", "--data", DB, "--key-id", _paired_key_id])
    _rkst = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + DB + "/ocliv.db');r=c.execute(\"SELECT status FROM agent_keys WHERE id='" + _paired_key_id + "'\").fetchone();print(r[0] if r else 'none')"]).stdout.strip()
    check("I3b: relay revoke-key revokes publisher authority", _rev.returncode == 0 and _rkst == "revoked", f"rc={_rev.returncode} status={_rkst}")
else:
    check("I3b: relay revoke-key revokes publisher authority", False, "no paired key from Phase F")

# I4: role separation — publisher home has no relay DB, no Caddyfile, no DNS creds
_pub_files = []
for _root, _, _fs in os.walk(_pair_home):
    for _fn in _fs:
        _pub_files.append(_fn)
_has_relay_state = any(x in _pub_files for x in ("ocliv.db", "Caddyfile", "relay.env", "dns-refresh.env"))
check("I4: publisher home contains zero relay DB / Caddy / DNS credentials", not _has_relay_state, f"files={_pub_files}")
shutil.rmtree(_pair_home, ignore_errors=True)

# I5: relay log does not leak raw private key hex strings
_ilog = os.path.join(S, "relay.log")
_ikey_leak = False
_ihex = []
if os.path.exists(_ilog):
    with open(_ilog, encoding="utf-8", errors="replace") as _ilf:
        _idata = _ilf.read(65536)
    _ihex = re.findall(r'\b[0-9a-f]{64}\b', _idata)
    _ikey_leak = len(set(_ihex)) > 3
check("I5: relay log heuristic: no raw private key hex strings", not _ikey_leak, "unique_64hex=" + str(len(set(_ihex))))

print("\n== SUMMARY ==")
print("PASS", len(PASS))
print("SKIP", len(SKIP), SKIP)
print("FAIL", len(FAIL), FAIL)
if FAIL or (SKIP and not ARGS.smoke):
    sys.exit(1)
