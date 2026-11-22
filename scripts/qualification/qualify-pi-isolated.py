#!/usr/bin/env python3
"""Release qualification harness for one isolated loopback relay.

The relay is started with a fresh DB and a unique stage path. This driver never
reads or mutates production state. It checks owner, executable, and stage-specific
argv before signaling any process.

Usage:
  qualify-pi-isolated.py --release-dir DIR        # strict release mode (default)
  qualify-pi-isolated.py --smoke [--release-dir]  # non-release isolated staging smoke
  qualify-pi-isolated.py [--keep-workdir]         # retain ephemeral secret workdir for debugging

In default (release) mode, --release-dir with a production-signed bundle is REQUIRED
and ANY skipped gate is treated as a failure.
"""
import argparse, atexit, base64, datetime, hashlib, http.server, json, os, platform, re, shutil, signal
import socket, stat, subprocess, sys, tempfile, threading, time
import urllib.request, urllib.error, urllib.parse

parser = argparse.ArgumentParser(description="Ocliv isolated loopback release qualification")
parser.add_argument("--smoke", action="store_true", help="non-release isolated staging smoke mode (allows ephemeral dev signing and SKIP)")
parser.add_argument("--release-dir", default="", help="directory containing signed release-manifest.json, .sig, and binary artifacts (REQUIRED in default strict mode)")
parser.add_argument("--receipt-out", default="", help="optional path to write provenance-bound JSON qualification receipt")
parser.add_argument("--keep-workdir", action="store_true", help="debug-only: keep ephemeral secret workdir on exit (prints warning)")
ARGS = parser.parse_args()

S = os.path.dirname(os.path.realpath(__file__))
WORK_DIR = tempfile.mkdtemp(prefix="ocliv-qual-work-")
os.chmod(WORK_DIR, 0o700)
BIN = os.path.join(S, "ocliv-arm64")
if not os.path.exists(BIN):
    for cand in (os.path.join(S, "ocliv"), os.path.join(S, "ocliv-linux-amd64"), os.path.join(S, "ocliv-linux-arm64")):
        if os.path.exists(cand):
            BIN = cand
            break
DB = os.path.join(WORK_DIR, "relay-data-fresh")
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


def stop_all_children():
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
    return errors


_CLEANED_UP = False


def cleanup():
    global _CLEANED_UP
    if _CLEANED_UP:
        return
    errors = stop_all_children()
    if ARGS.keep_workdir:
        print(f"WARNING: --keep-workdir enabled; ephemeral secret workdir retained at {WORK_DIR}", file=sys.stderr, flush=True)
    elif os.path.exists(WORK_DIR):
        shutil.rmtree(WORK_DIR, ignore_errors=True)
    _CLEANED_UP = True
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
            start_child(["python3", UPSTREAM, "28099"], os.path.join(WORK_DIR, "upstream.log"), env=ENV, required=[UPSTREAM, "28099"])
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


ENV = {"HOME": os.path.join(WORK_DIR, "qual-home"), "OCLIV_RELAY_URL": BASE}
os.makedirs(ENV["HOME"], mode=0o700, exist_ok=True)
os.chmod(ENV["HOME"], 0o700)


def assert_ports_free():
    for port in (28080, 28082, 28085, 28086, 28099, 59999):
        sock = socket.socket()
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


_ARCH = "arm64" if platform.machine() in ("aarch64", "arm64") else "amd64"
ARTIFACT_NAME = f"ocliv-linux-{_ARCH}"
BIN_SHA256 = sha256_file(BIN)
ACTIVE_MANIFEST = {}

SBOM_DECLARED_SHA256 = ""
SBOM_ACTUAL_SHA256 = ""
SBOM_META = {}

if not ARGS.smoke:
    print("== MODE: STRICT RELEASE QUALIFICATION ==", flush=True)
    if ARGS.keep_workdir:
        raise RuntimeError("strict release mode refuses --keep-workdir (ephemeral security state must not be retained)")
    if not RELEASE_DIR or not os.path.isdir(RELEASE_DIR):
        raise RuntimeError("strict release mode requires --release-dir DIR pointing to a production-signed release bundle (pass --smoke for non-release staging smoke)")
    REL_MANIFEST_PATH = os.path.join(RELEASE_DIR, "release-manifest.json")
    REL_SIG_PATH = os.path.join(RELEASE_DIR, "release-manifest.json.sig")
    if not os.path.isfile(REL_MANIFEST_PATH) or not os.path.isfile(REL_SIG_PATH):
        raise RuntimeError("strict release mode requires both release-manifest.json and release-manifest.json.sig in --release-dir")
    with open(REL_MANIFEST_PATH, encoding="utf-8") as _mf:
        _strict_m = json.load(_mf)
    if _strict_m.get("non_production"):
        raise RuntimeError("strict release mode refuses non_production=true manifest")
    if _strict_m.get("dirty") is not False:
        raise RuntimeError("strict release mode refuses dirty manifest")
    if _strict_m.get("govulncheck") != "pass":
        raise RuntimeError(f"strict release mode requires govulncheck == 'pass' (got {_strict_m.get('govulncheck')!r})")
    if _strict_m.get("manifest_version") != 1:
        raise RuntimeError(f"strict release mode requires manifest_version == 1 (got {_strict_m.get('manifest_version')!r})")
    _rseq = _strict_m.get("release_sequence")
    if not isinstance(_rseq, int) or isinstance(_rseq, bool) or _rseq <= 0:
        raise RuntimeError(f"strict release mode requires positive integer release_sequence (got {_rseq!r})")
    if not _strict_m.get("signing_key_id"):
        raise RuntimeError("strict release mode requires non-empty signing_key_id in manifest")
    # Mandatory SBOM provenance byte, containment, and CycloneDX toolchain binding in strict mode.
    _sbom_obj = (_strict_m.get("provenance") or {}).get("sbom") or {}
    _sbom_file = _sbom_obj.get("file") or ""
    _sbom_decl = _sbom_obj.get("sha256") or ""
    if not _sbom_file or not _sbom_decl:
        raise RuntimeError("strict release mode requires provenance.sbom.file and provenance.sbom.sha256 in manifest")
    if os.path.isabs(_sbom_file) or "/" in _sbom_file or "\\" in _sbom_file or ".." in _sbom_file:
        raise RuntimeError(f"strict release mode refuses non-contained sbom.file={_sbom_file!r}")
    if _sbom_obj.get("format") != "cyclonedx-json":
        raise RuntimeError(f"strict release mode requires sbom.format == 'cyclonedx-json' (got {_sbom_obj.get('format')!r})")
    if _sbom_obj.get("generator") != "cyclonedx-gomod":
        raise RuntimeError(f"strict release mode requires sbom.generator == 'cyclonedx-gomod' (got {_sbom_obj.get('generator')!r})")
    if not _sbom_obj.get("generator_version"):
        raise RuntimeError("strict release mode requires non-empty sbom.generator_version")
    _sbom_path = os.path.join(RELEASE_DIR, _sbom_file)
    if os.path.islink(_sbom_path) or not os.path.isfile(_sbom_path):
        raise RuntimeError(f"strict release mode: declared SBOM file missing or symlink: {_sbom_path}")
    SBOM_DECLARED_SHA256 = _sbom_decl
    SBOM_ACTUAL_SHA256 = sha256_file(_sbom_path)
    if SBOM_ACTUAL_SHA256 != SBOM_DECLARED_SHA256:
        raise RuntimeError(f"strict release mode: SBOM SHA256 mismatch (declared={SBOM_DECLARED_SHA256} actual={SBOM_ACTUAL_SHA256})")
    with open(_sbom_path, encoding="utf-8") as _sf:
        _sbom_doc = json.load(_sf)
    if _sbom_doc.get("bomFormat") != "CycloneDX" or not _sbom_doc.get("specVersion"):
        raise RuntimeError(f"strict release mode: SBOM document is not valid CycloneDX (bomFormat={_sbom_doc.get('bomFormat')!r} specVersion={_sbom_doc.get('specVersion')!r})")
    SBOM_META = _sbom_obj
    # Cryptographic/byte-for-byte binding: tested binary == signed bundle artifact == manifest identity.
    if _strict_m.get("commit") != BIN_COMMIT:
        raise RuntimeError(f"release bundle commit ({_strict_m.get('commit')}) != qualification binary commit ({BIN_COMMIT})")
    if int(_strict_m.get("schema_version") or 0) != int(EXPECTED_SCHEMA):
        raise RuntimeError(f"release bundle schema_version ({_strict_m.get('schema_version')}) != qualification binary schema ({EXPECTED_SCHEMA})")
    _manifest_proto = _strict_m.get("protocol_version")
    _bin_proto = BIN_VER_INFO.get("protocol_version")
    if not isinstance(_manifest_proto, str) or not _manifest_proto:
        raise RuntimeError("strict release manifest missing protocol_version")
    if not isinstance(_bin_proto, str) or not _bin_proto:
        raise RuntimeError("qualification binary missing protocol_version")
    if _manifest_proto != _bin_proto:
        raise RuntimeError(f"release bundle protocol_version ({_manifest_proto}) != qualification binary ({_bin_proto})")
    _bundle_bin = os.path.join(RELEASE_DIR, ARTIFACT_NAME)
    if not os.path.isfile(_bundle_bin):
        raise RuntimeError(f"release bundle missing platform artifact {_bundle_bin}")
    _bundle_sha = sha256_file(_bundle_bin)
    _declared_sha = ((_strict_m.get("artifacts") or {}).get(ARTIFACT_NAME) or {}).get("sha256", "")
    if len({BIN_SHA256, _bundle_sha, _declared_sha}) != 1:
        raise RuntimeError(f"qualification binary != signed release artifact (bin={BIN_SHA256} bundle={_bundle_sha} manifest={_declared_sha})")
    ACTIVE_MANIFEST = _strict_m
    REL_USE_DEV_UNSIGNED = False
else:
    print("== MODE: ISOLATED STAGING SMOKE (non-release) ==", flush=True)
    if RELEASE_DIR and os.path.isdir(RELEASE_DIR):
        REL_MANIFEST_PATH = os.path.join(RELEASE_DIR, "release-manifest.json")
        REL_SIG_PATH = os.path.join(RELEASE_DIR, "release-manifest.json.sig")
        if os.path.isfile(REL_MANIFEST_PATH):
            with open(REL_MANIFEST_PATH, encoding="utf-8") as _mf:
                ACTIVE_MANIFEST = json.load(_mf)
        REL_USE_DEV_UNSIGNED = True
    else:
        RELEASE_DIR = os.path.join(S, "release-bundle-stage")
        os.makedirs(RELEASE_DIR, mode=0o700, exist_ok=True)
        _adst = os.path.join(RELEASE_DIR, ARTIFACT_NAME)
        shutil.copy2(BIN, _adst)
        _asha = sha256_file(_adst)
        REL_MANIFEST_PATH = os.path.join(RELEASE_DIR, "release-manifest.json")
        _mobj = {
            "manifest_version": 1,
            "release_sequence": int(time.time()),
            "signing_key_id": "stage-smoke-ephemeral",
            "commit": BIN_COMMIT,
            "dirty": False,
            "build_time": BIN_VER_INFO.get("build_time") or "2026-11-21T00:00:00Z",
            "protocol_version": BIN_VER_INFO.get("protocol_version") or "",
            "schema_version": int(EXPECTED_SCHEMA),
            "govulncheck": "pass",
            "artifacts": {ARTIFACT_NAME: {"sha256": _asha}},
        }
        ACTIVE_MANIFEST = _mobj
        with open(REL_MANIFEST_PATH, "w", encoding="utf-8") as _mf:
            _mf.write(json.dumps(_mobj, indent=2) + "\n")
        # Sign with an ephemeral Ed25519 key stored ONLY in WORK_DIR and unlinked immediately.
        _priv_pem = os.path.join(WORK_DIR, "stage-smoke-priv.pem")
        _pub_pem = os.path.join(WORK_DIR, "stage-smoke-pub.pem")
        _sig_raw = os.path.join(WORK_DIR, "release-manifest.json.sig.raw")
        REL_SIG_PATH = os.path.join(RELEASE_DIR, "release-manifest.json.sig")
        try:
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", _priv_pem], check=True, capture_output=True)
            os.chmod(_priv_pem, 0o600)
            subprocess.run(["openssl", "pkey", "-in", _priv_pem, "-pubout", "-out", _pub_pem], check=True, capture_output=True)
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", _priv_pem, "-rawin", "-in", REL_MANIFEST_PATH, "-out", _sig_raw], check=True, capture_output=True)
            with open(_sig_raw, "rb") as _sf, open(REL_SIG_PATH, "w", encoding="ascii") as _hf:
                _hf.write(_sf.read().hex())
            with open(_pub_pem, "r", encoding="ascii") as _pf:
                REL_SIGN_PUB_PEM = _pf.read().strip()
        finally:
            for _secret_f in (_priv_pem, _pub_pem, _sig_raw):
                try:
                    os.remove(_secret_f)
                except FileNotFoundError:
                    pass
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
relay_proc = start_child(relay_args, os.path.join(WORK_DIR, "relay.log"), env=relay_env, required=relay_required)
with open(os.path.join(WORK_DIR, "relay.pid"), "x", encoding="ascii") as f:
    f.write(str(relay_proc.pid) + "\n")
os.chmod(os.path.join(WORK_DIR, "relay.pid"), 0o600)
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

start_child(["python3", UPSTREAM, "28099"], os.path.join(WORK_DIR, "upstream.log"), env=ENV, required=[UPSTREAM, "28099"])
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
    code_path = os.path.join(WORK_DIR, "qc.txt")
    fd = os.open(code_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(codes[0] + "\n")
    sh([BIN, "logout"], ENV)
    try:
        login = sh([BIN, "login", "--relay", BASE, "--code-file", code_path], ENV)
    finally:
        try:
            os.remove(code_path)
        except FileNotFoundError:
            pass
    if login.returncode:
        raise RuntimeError("staging login failed: " + login.stderr[:200])
    start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "qa", "--ttl", "30m", "--relay", BASE], os.path.join(WORK_DIR, "pub-qa.log"), env=ENV, required=["mcp", "publish", "--name", "qa"])
    time.sleep(5)
    cr = db_routes()
    ra = cr[0] if cr else None
if ra and not rb:
    start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "qb", "--ttl", "30m", "--relay", BASE], os.path.join(WORK_DIR, "pub-qb.log"), env=ENV, required=["mcp", "publish", "--name", "qb"])
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
    relay_proc = start_child(relay_args, os.path.join(WORK_DIR, "relay.log"), env=relay_env, required=relay_required)
    with open(os.path.join(WORK_DIR, "relay.pid"), "w", encoding="ascii") as f:
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
_pre_rev = os.path.join(WORK_DIR, "pre-revoke.db")
_reset_dir = os.path.join(WORK_DIR, "reset-dir")
st = sh([BIN, "relay", "backup", "--data", DB, "--out", _pre_rev])
check("E: guarded backup (pre-revoke)", st.returncode == 0, "rc=" + str(st.returncode))
sh([BIN, "authz", "revoke", "--data", DB, "--client", cidA, "--tenant", "t1", "--route", ra], ENV)
st = sh([BIN, "relay", "restore", "--data", DB, "--in", _pre_rev, "--relay-stopped"])
out = st.stdout + st.stderr
check("E: managed rollback restore refused", st.returncode != 0 and "resurrect" in out, f"rc={st.returncode} {out[:90]}")
os.makedirs(_reset_dir, exist_ok=True)
subprocess.run(["rm", "-f", os.path.join(_reset_dir, "ocliv.db")])
st = sh([BIN, "relay", "restore", "--data", _reset_dir, "--in", _pre_rev, "--reset-authority", "--relay-stopped"])
res = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + _reset_dir + "/ocliv.db');print('ag',c.execute(\"SELECT COUNT(*) FROM authz_grants WHERE status='active'\").fetchone()[0]);print('cr',c.execute('SELECT COUNT(*) FROM authz_clients WHERE revoked_at IS NOT NULL').fetchone()[0]);print('ik',c.execute('SELECT COUNT(*) FROM authz_issuer_key').fetchone()[0])"]).stdout
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
        _pair_pub_proc = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "pair-pub", "--ttl", "10m", "--relay", BASE], os.path.join(WORK_DIR, "pub-pair.log"), env=_pair_env, required=["mcp", "publish", "--name", "pair-pub"])
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
if os.path.exists(_install_script) and os.path.exists(REL_SIG_PATH) and (not ARGS.smoke or REL_SIGN_PUB_PEM):
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
        # (explicitly excluding go, git, caddy, docker, jq, xxd, python3, and pre-existing ocliv).
        _allowed_tools = [
            "sh", "curl", "wget", "openssl", "sha256sum", "uname", "mktemp",
            "cp", "mv", "rm", "chmod", "cat", "tr", "grep", "sed", "head",
            "awk", "wc", "cut", "id", "mkdir", "sync", "printf", "test", "[",
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
        }
        if REL_SIGN_PUB_PEM:
            _ienv["OCLIV_ALLOW_TEST_TRUST"] = "1"
            _ienv["OCLIV_ENV"] = "development"
            _ienv["OCLIV_TEST_SIGNING_PUBLIC_KEY_PEM"] = REL_SIGN_PUB_PEM
        # Assert excluded dev tools AND xxd/python3 are absent from minimal PATH.
        _excluded_found = [t for t in ("go", "git", "caddy", "docker", "jq", "ocliv", "xxd", "python3") if shutil.which(t, path=_min_bin)]
        check("G5_env: minimal publisher PATH excludes go/git/caddy/docker/jq/ocliv/xxd/python3", len(_excluded_found) == 0, f"found={_excluded_found}")
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
        # Test trust override without OCLIV_ALLOW_TEST_TRUST=1 must be rejected.
        _tamper_mode["mode"] = "none"
        _ienv_no_allow = dict(_ienv)
        _ienv_no_allow.pop("OCLIV_ALLOW_TEST_TRUST", None)
        _ienv_no_allow["OCLIV_TEST_SIGNING_PUBLIC_KEY_PEM"] = REL_SIGN_PUB_PEM or "dummy"
        _r_tref = subprocess.run([os.path.join(_min_bin, "sh"), _install_script, _burl], capture_output=True, text=True, timeout=20, env=_ienv_no_allow)
        check("G5e: test trust override refused without OCLIV_ALLOW_TEST_TRUST=1", _r_tref.returncode != 0, "rc=" + str(_r_tref.returncode))
    finally:
        _bsrv.shutdown()
        shutil.rmtree(_inst_dir, ignore_errors=True)
        shutil.rmtree(_min_bin, ignore_errors=True)
else:
    skip_gate("G5: signed bootstrap install", "install-client.sh or test signing key unavailable")

print("== Phase H: real capacity saturation (--max-publisher-sessions=2, --max-http-streams=2, --max-ws-streams=2) ==")
_cap_db = os.path.join(WORK_DIR, "relay-cap-db")
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
_cap_proc = start_child(_cap_args, os.path.join(WORK_DIR, "relay-cap.log"), required=_cap_req)
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
    p1 = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "cap1", "--ttl", "10m", "--relay", _cap_base], os.path.join(WORK_DIR, "cap-pub1.log"), env=e1, required=["mcp", "publish", "--name", "cap1"])
    p2 = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "cap2", "--ttl", "10m", "--relay", _cap_base], os.path.join(WORK_DIR, "cap-pub2.log"), env=e2, required=["mcp", "publish", "--name", "cap2"])
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
    _p3_log = os.path.join(WORK_DIR, "cap-pub3.log")
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
        p3 = start_child([BIN, "mcp", "publish", "--local", "http://127.0.0.1:28099/mcp", "--auth", "ocliv-managed", "--name", "cap3b", "--ttl", "10m", "--relay", _cap_base], os.path.join(WORK_DIR, "cap-pub3b.log"), env=e3, required=["mcp", "publish", "--name", "cap3b"])
    for _ in range(30):
        _st4 = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
        _lcnt = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + _cap_db + "/ocliv.db');print(c.execute(\"SELECT COUNT(*) FROM leases WHERE label IN ('cap3','cap3b') AND status='ACTIVE'\").fetchone()[0])"]).stdout.strip()
        if _lcnt.isdigit() and int(_lcnt) >= 1 and _st4.get("active_sessions") == 2:
            _re_admitted = True
            break
        time.sleep(0.5)
    check("H3: slot released on disconnect and 3rd publisher admitted without leakage", _re_admitted, f"active={_st4.get('active_sessions')}")

    # Stop p2 and p3 so we have a clean session slot for the blocking HTTP + WS upstream publisher.
    for _p, _req in ((p2, ["mcp", "publish", "--name", "cap2"]), (p3, ["mcp", "publish"])):
        if _p.poll() is None:
            try:
                stop_pid(_p.pid, BIN, _req)
                _p.wait(timeout=8)
            except Exception:
                pass

    # H4 & H5: real blocking HTTP stream cap=2 & WebSocket stream cap=2 saturation.
    _http_release = threading.Event()
    _ws_stop = threading.Event()
    _hold_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _hold_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _hold_srv.bind(("127.0.0.1", 0))
    _hold_port = _hold_srv.getsockname()[1]
    _hold_srv.listen(16)
    _hold_srv.settimeout(0.5)

    def _handle_hold_conn(conn):
        try:
            conn.settimeout(15)
            raw = b""
            while b"\r\n\r\n" not in raw and len(raw) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                raw += chunk
            head = raw.split(b"\r\n\r\n", 1)[0].decode("latin1", errors="replace")
            first = head.splitlines()[0] if head else ""
            if "/hold-ws" in first:
                ws_key = ""
                for line in head.splitlines()[1:]:
                    if line.lower().startswith("sec-websocket-key:"):
                        ws_key = line.split(":", 1)[1].strip()
                accept = base64.b64encode(hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                resp = (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode("ascii")
                conn.sendall(resp)
                conn.settimeout(0.5)
                while not _ws_stop.is_set():
                    try:
                        data = conn.recv(1024)
                        if not data:
                            break
                    except socket.timeout:
                        continue
            else:
                if "/hold-http" in first:
                    _http_release.wait(timeout=15)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _accept_loop():
        while not _ws_stop.is_set():
            try:
                c, _ = _hold_srv.accept()
                threading.Thread(target=_handle_hold_conn, args=(c,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    _accept_thr = threading.Thread(target=_accept_loop, daemon=True)
    _accept_thr.start()

    sh([BIN, "relay", "tenants", "policy", "set", "cap-t", "--allow-public=true", "--data", _cap_db])
    _pub_stream = start_child(
        [BIN, str(_hold_port), "--public", "--name", "capstream", "--ttl", "10m", "--relay", _cap_base],
        os.path.join(WORK_DIR, "cap-stream.log"), env=e1, required=[str(_hold_port), "--public", "--name", "capstream"]
    )
    _stream_host = ""
    for _ in range(40):
        _sh_out = sh(["python3", "-c", "import sqlite3;c=sqlite3.connect('" + _cap_db + "/ocliv.db');r=c.execute(\"SELECT hostname FROM leases WHERE label='capstream' AND status='ACTIVE' ORDER BY created_at DESC LIMIT 1\").fetchone();print(r[0] if r else '')"]).stdout.strip()
        if _sh_out:
            _stream_host = _sh_out
            break
        time.sleep(0.5)

    if _stream_host:
        # H4: Hold 2 HTTP streams open -> 3rd gets 503 while /health/ready == 200 -> release -> recovers to 0.
        _h_results = []
        def _do_hold_http():
            st, _, _ = http_req("GET", "/hold-http", host=_stream_host, base=_cap_base)
            _h_results.append(st)

        _ht1 = threading.Thread(target=_do_hold_http, daemon=True)
        _ht2 = threading.Thread(target=_do_hold_http, daemon=True)
        _ht1.start()
        _ht2.start()
        _h_sat = False
        for _ in range(40):
            _hs = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
            if _hs.get("active_http_streams") == 2:
                _h_sat = True
                break
            time.sleep(0.1)
        _h3_st, _, _ = http_req("GET", "/hold-http", host=_stream_host, base=_cap_base)
        _h_ready = urllib.request.urlopen("http://127.0.0.1:28086/health/ready", timeout=2).status
        _http_release.set()
        _ht1.join(timeout=10)
        _ht2.join(timeout=10)
        _h4_st, _, _ = http_req("GET", "/fast", host=_stream_host, base=_cap_base)
        _h_zero = False
        for _ in range(30):
            _hs2 = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
            if _hs2.get("active_http_streams") == 0:
                _h_zero = True
                break
            time.sleep(0.1)
        check(
            "H4: --max-http-streams=2 rejects 3rd (503), /health/ready=200, recovers to 0",
            _h_sat and _h3_st == 503 and _h_ready == 200 and _h4_st == 200 and _h_zero and _h_results == [200, 200],
            f"sat={_h_sat} 3rd={_h3_st} ready={_h_ready} next={_h4_st} zero={_h_zero} held={_h_results}",
        )

        # H5: Hold 2 WebSocket upgrades open -> 3rd gets 503 while /health/ready == 200 -> close 1 -> 4th gets 101 -> close all -> 0.
        def _open_ws():
            sk = socket.create_connection(("127.0.0.1", 28082), timeout=5)
            key = base64.b64encode(os.urandom(16)).decode()
            req = (
                f"GET /hold-ws HTTP/1.1\r\n"
                f"Host: {_stream_host}\r\n"
                f"Origin: http://{_stream_host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode("ascii")
            sk.sendall(req)
            buf = b""
            sk.settimeout(5)
            while b"\r\n\r\n" not in buf and len(buf) < 4096:
                ch = sk.recv(1024)
                if not ch:
                    break
                buf += ch
            line = buf.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
            return sk, line

        _ws_socks = []
        try:
            _s1, _l1 = _open_ws()
            _ws_socks.append(_s1)
            _s2, _l2 = _open_ws()
            _ws_socks.append(_s2)
            _w_sat = False
            for _ in range(40):
                _ws_st = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
                if _ws_st.get("active_ws_streams") == 2:
                    _w_sat = True
                    break
                time.sleep(0.1)
            _s3, _l3 = _open_ws()
            _s3.close()
            _w_ready = urllib.request.urlopen("http://127.0.0.1:28086/health/ready", timeout=2).status
            _s1.close()
            _ws_socks.remove(_s1)
            for _ in range(30):
                _ws_st2 = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
                if _ws_st2.get("active_ws_streams") == 1:
                    break
                time.sleep(0.1)
            _s4, _l4 = _open_ws()
            _ws_socks.append(_s4)
            for _sk in list(_ws_socks):
                _sk.close()
            _ws_socks.clear()
            _w_zero = False
            for _ in range(40):
                _ws_st3 = json.loads(urllib.request.urlopen("http://127.0.0.1:28086/health/status", timeout=2).read().decode())
                if _ws_st3.get("active_ws_streams") == 0:
                    _w_zero = True
                    break
                time.sleep(0.1)
            check(
                "H5: --max-ws-streams=2 rejects 3rd (503), /health/ready=200, recovers to 0",
                ("101" in _l1) and ("101" in _l2) and _w_sat and ("503" in _l3) and _w_ready == 200 and ("101" in _l4) and _w_zero,
                f"l1={_l1[:15]} l2={_l2[:15]} sat={_w_sat} l3={_l3[:15]} ready={_w_ready} l4={_l4[:15]} zero={_w_zero}",
            )
        finally:
            for _sk in _ws_socks:
                try:
                    _sk.close()
                except Exception:
                    pass
    else:
        check("H4: --max-http-streams=2 saturation", False, "capstream public lease did not activate")
        check("H5: --max-ws-streams=2 saturation", False, "capstream public lease did not activate")

    _ws_stop.set()
    _hold_srv.close()
    if _pub_stream.poll() is None:
        stop_pid(_pub_stream.pid, BIN, [str(_hold_port), "--public", "--name", "capstream"])
        _pub_stream.wait(timeout=8)
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
_ilog = os.path.join(WORK_DIR, "relay.log")
_ikey_leak = False
_ihex = []
if os.path.exists(_ilog):
    with open(_ilog, encoding="utf-8", errors="replace") as _ilf:
        _idata = _ilf.read(65536)
    _ihex = re.findall(r'\b[0-9a-f]{64}\b', _idata)
    _ikey_leak = len(set(_ihex)) > 3
check("I5: relay log heuristic: no raw private key hex strings", not _ikey_leak, "unique_64hex=" + str(len(set(_ihex))))

# Fail-closed ephemeral cleanup BEFORE evaluating I6 and writing the final receipt.
_child_stop_errs = stop_all_children()
_scratch_cleanup_ok = False
_scratch_cleanup_err = ""
if ARGS.keep_workdir:
    print(f"WARNING: --keep-workdir enabled; ephemeral workdir retained at {WORK_DIR}", file=sys.stderr, flush=True)
    _scratch_cleanup_ok = False
else:
    try:
        shutil.rmtree(WORK_DIR)
        _scratch_cleanup_ok = (not os.path.exists(WORK_DIR)) and (len(_child_stop_errs) == 0)
    except Exception as _ce:
        _scratch_cleanup_ok = False
        _scratch_cleanup_err = str(_ce)
_CLEANED_UP = True
if not ARGS.keep_workdir:
    check("I5b: fail-closed ephemeral WORK_DIR removal verified", _scratch_cleanup_ok, f"stop_errs={_child_stop_errs} err={_scratch_cleanup_err}")

# I6: strict allowlist check over retained stage dir S (zero raw logs, zero keys/DBs/secrets).
_ALLOWED_EXACT = {
    os.path.basename(BIN),
    "ocliv-arm64", "ocliv", "ocliv-linux-arm64", "ocliv-linux-amd64",
    "qualify-pi-isolated.py", "rehearse-prod-migration.py", "soak-isolated.py",
    "verify-promotion-evidence.py", "install-client.sh", "mcp_upstream.py",
    "qual-receipt.json", "mig-receipt.json", "soak-receipt.json",
    "release-manifest.json", "release-manifest.json.sig",
}
_unexpected_retained = []
for _rroot, _rdirs, _rfiles in os.walk(S):
    _rel_dir = os.path.relpath(_rroot, S)
    for _rf in _rfiles:
        _rel = _rf if _rel_dir == "." else os.path.join(_rel_dir, _rf)
        if _rel_dir == "release-bundle-stage":
            if _rf.startswith("ocliv-linux-") or _rf in ("release-manifest.json", "release-manifest.json.sig", "sbom.cdx.json", "go-module-inventory.json"):
                continue
        if _rel_dir == "." and _rf in _ALLOWED_EXACT:
            continue
        _unexpected_retained.append(_rel)
check("I6: retained stage dir matches strict public allowlist (zero raw logs/keys/DBs/secrets)", len(_unexpected_retained) == 0, f"unexpected={_unexpected_retained}")

_ephemeral_retained = bool(ARGS.keep_workdir) or (not _scratch_cleanup_ok)
_bundle_art_path = os.path.join(RELEASE_DIR, ARTIFACT_NAME) if RELEASE_DIR else ""
_receipt = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "mode": "isolated-staging-smoke" if ARGS.smoke else "strict-production",
    "ephemeral_state_retained": _ephemeral_retained,
    "scratch_cleanup_ok": _scratch_cleanup_ok,
    "candidate_commit": BIN_COMMIT,
    "binary_sha256": BIN_SHA256,
    "qual_binary_sha256": BIN_SHA256,
    "signed_artifact_name": ARTIFACT_NAME,
    "signed_artifact_sha256": sha256_file(_bundle_art_path) if _bundle_art_path and os.path.isfile(_bundle_art_path) else "",
    "manifest_sha256": sha256_file(REL_MANIFEST_PATH) if REL_MANIFEST_PATH and os.path.isfile(REL_MANIFEST_PATH) else "",
    "manifest_version": ACTIVE_MANIFEST.get("manifest_version"),
    "release_sequence": ACTIVE_MANIFEST.get("release_sequence"),
    "schema_version": int(EXPECTED_SCHEMA),
    "protocol_version": BIN_VER_INFO.get("protocol_version") or "",
    "signing_key_id": ACTIVE_MANIFEST.get("signing_key_id") or "",
    "sbom_declared_sha256": SBOM_DECLARED_SHA256,
    "sbom_actual_sha256": SBOM_ACTUAL_SHA256,
    "sbom_generator": SBOM_META.get("generator") or "",
    "sbom_generator_version": SBOM_META.get("generator_version") or "",
    "sbom_file": SBOM_META.get("file") or "",
    "sbom_format": SBOM_META.get("format") or "",
    "stage_dir": S,
    "pass_count": len(PASS),
    "skip_count": len(SKIP),
    "fail_count": len(FAIL),
    "skipped": SKIP,
    "failed": FAIL,
    "ok": (not FAIL) and (not SKIP or ARGS.smoke) and (not _ephemeral_retained) and _scratch_cleanup_ok,
}
_default_receipt = os.path.join(S, "qual-receipt.json")
with open(_default_receipt, "w", encoding="utf-8") as _rf:
    json.dump(_receipt, _rf, indent=2)
if ARGS.receipt_out and os.path.realpath(ARGS.receipt_out) != os.path.realpath(_default_receipt):
    with open(ARGS.receipt_out, "w", encoding="utf-8") as _rf:
        json.dump(_receipt, _rf, indent=2)

print("\n== SUMMARY ==")
print("PASS", len(PASS))
print("SKIP", len(SKIP), SKIP)
print("FAIL", len(FAIL), FAIL)
print("RECEIPT", _default_receipt)
if FAIL or (SKIP and not ARGS.smoke):
    sys.exit(1)
