#!/usr/bin/env python3
"""Isolated dual-lane workload soak driver for Ocliv relay + persistent publishers.

Runs an isolated loopback relay, a local HTTP upstream, and TWO live publisher lanes:
  - Lane 1 (managed auth): `ocliv mcp publish --auth ocliv-managed` — verifies unauthenticated
    requests return 401.
  - Lane 2 (data plane): `ocliv <port> --public` — sends unique-nonce GET requests through
    relay -> publisher -> local upstream and asserts HTTP 200 with exact echoed `soak_nonce`
    and monotonically advancing upstream hit counter.
  - Deliberate mid-soak publisher disconnect/reconnect: proves Lane 2 FAILS while publisher
    is disconnected and RECOVERS to 200 + exact nonce after reconnect.
  - Deterministic pairing 429 recovery state machine: any 429 sets `recovery_required=True`
    (even after earlier recoveries); only a subsequent 200 clears it. Ending with
    `recovery_required=True` FAILS.
  - Fail-closed scratch cleanup: verifies complete removal of temporary dir before writing
    the final PASS receipt.
  - `--release-gate` enforces 24h duration, >=300s warm-up, >=720s drain, <=60s interval,
    mandatory `--receipt-out`, and mandatory `--qualification-receipt` binding.

Usage:
  soak-isolated.py --bin /path/to/ocliv --release-gate \
      --qualification-receipt qual-receipt.json --receipt-out soak-24h.json
  soak-isolated.py --bin /path/to/ocliv --duration 20 --sample-interval 5 --receipt-out soak-smoke.json
  soak-isolated.py --self-test
"""
import argparse, base64, datetime, hashlib, http.server, json, math, os, shutil, socket, sqlite3, statistics
import subprocess, sys, tempfile, threading, time, urllib.error, urllib.parse, urllib.request

PAIRING_TTL_SEC = 600  # 10-minute pairing request expiry


class PairingRecoveryTracker:
    """Deterministic 429 recovery state machine."""

    def __init__(self):
        self.saw_429 = False
        self.recovery_required = False
        self.recovery_events = 0
        self.consecutive_429 = 0
        self.max_consecutive_429 = 0
        self.last_429_at = None
        self.last_recovery_at = None

    def record(self, status, ts_iso):
        if status == 429:
            self.saw_429 = True
            self.recovery_required = True
            self.consecutive_429 += 1
            self.max_consecutive_429 = max(self.max_consecutive_429, self.consecutive_429)
            self.last_429_at = ts_iso
        elif status == 200:
            if self.recovery_required:
                self.recovery_events += 1
                self.last_recovery_at = ts_iso
            self.recovery_required = False
            self.consecutive_429 = 0


def run_self_test():
    # Sequence 429 -> 200 -> 429 with no final 200 MUST end with recovery_required == True.
    t = PairingRecoveryTracker()
    t.record(429, "t1")
    assert t.recovery_required is True and t.recovery_events == 0
    t.record(200, "t2")
    assert t.recovery_required is False and t.recovery_events == 1 and t.last_recovery_at == "t2"
    t.record(429, "t3")
    assert t.recovery_required is True and t.saw_429 is True and t.last_429_at == "t3"
    # Final 200 clears recovery_required.
    t.record(200, "t4")
    assert t.recovery_required is False and t.recovery_events == 2 and t.last_recovery_at == "t4"
    print("SOAK_SELF_TEST=OK")


parser = argparse.ArgumentParser(description="Ocliv isolated dual-lane workload soak driver")
parser.add_argument("--bin", default="", help="Path to candidate ocliv binary")
parser.add_argument("--duration", type=int, default=86400, help="Soak duration in seconds (default 86400 = 24h)")
parser.add_argument("--warmup", type=int, default=-1, help="Warm-up period in seconds (-1 auto: 300s if duration>=600 else 0)")
parser.add_argument("--drain", type=int, default=-1, help="Final pairing drain/recovery window in seconds (-1 auto: 720s if duration>=3600 else 0)")
parser.add_argument("--sample-interval", type=int, default=60, help="Sampling interval in seconds")
parser.add_argument("--qualification-receipt", default="", help="Strict qualification receipt JSON to bind candidate provenance (required with --release-gate)")
parser.add_argument("--receipt-out", default="", help="Path to write provenance-bound JSON soak receipt (required with --release-gate)")
parser.add_argument("--release-gate", action="store_true", help="Enforce strict 24h release-gate parameters")
parser.add_argument("--self-test", action="store_true", help="Run deterministic unit self-test for 429 recovery state machine and exit")
args = parser.parse_args()

if args.self_test:
    run_self_test()
    sys.exit(0)

if not args.bin:
    raise SystemExit("error: --bin is required")

warmup_sec = args.warmup if args.warmup >= 0 else (300 if args.duration >= 600 else 0)
drain_sec = args.drain if args.drain >= 0 else (720 if args.duration >= 3600 else 0)

if args.release_gate:
    if args.duration < 86400:
        raise SystemExit(f"--release-gate requires --duration >= 86400 (got {args.duration})")
    if warmup_sec < 300:
        raise SystemExit(f"--release-gate requires --warmup >= 300 (got {warmup_sec})")
    if drain_sec < 720:
        raise SystemExit(f"--release-gate requires --drain >= 720 (got {drain_sec})")
    if args.sample_interval > 60 or args.sample_interval <= 0:
        raise SystemExit(f"--release-gate requires 1 <= --sample-interval <= 60 (got {args.sample_interval})")
    if not args.receipt_out:
        raise SystemExit("--release-gate requires --receipt-out PATH")
    if not args.qualification_receipt:
        raise SystemExit("--release-gate requires --qualification-receipt PATH")


def pick_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def series_stats(xs, ts):
    if not xs:
        return {}
    s_xs = sorted(xs)
    p95_idx = min(len(s_xs) - 1, int(0.95 * (len(s_xs) - 1)))
    slope_per_hr = 0.0
    if len(xs) >= 2 and ts[-1] > ts[0]:
        t_mean = statistics.mean(ts)
        x_mean = statistics.mean(xs)
        denom = sum((t - t_mean) ** 2 for t in ts)
        if denom > 0:
            slope_per_sec = sum((t - t_mean) * (x - x_mean) for t, x in zip(ts, xs)) / denom
            slope_per_hr = round(slope_per_sec * 3600.0, 4)
    return {
        "start": xs[0],
        "end": xs[-1],
        "min": s_xs[0],
        "median": statistics.median(s_xs),
        "p95": s_xs[p95_idx],
        "max": s_xs[-1],
        "slope_per_hour": slope_per_hr,
    }


UPSTREAM_LOCK = threading.Lock()
UPSTREAM_HITS = {"count": 0}


class _UpstreamHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        nonce = (qs.get("nonce") or [""])[0]
        with UPSTREAM_LOCK:
            UPSTREAM_HITS["count"] += 1
            hit = UPSTREAM_HITS["count"]
        data = json.dumps({"soak_nonce": nonce, "upstream_hits": hit}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(ln)
        data = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "ping"}]}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


ver_res = subprocess.run([args.bin, "version", "--json"], capture_output=True, text=True)
if ver_res.returncode != 0:
    print("FAIL: candidate binary failed version --json:", ver_res.stderr, file=sys.stderr)
    sys.exit(1)
ver_info = json.loads(ver_res.stdout)
cand_commit = ver_info.get("build_commit") or ver_info.get("commit") or ""
bin_sha = sha256_file(args.bin)

bound_provenance = {}
if args.qualification_receipt:
    with open(args.qualification_receipt, encoding="utf-8") as qf:
        qr = json.load(qf)
    errs = []
    if qr.get("mode") != "strict-production":
        errs.append(f"mode={qr.get('mode')!r} != 'strict-production'")
    if qr.get("ok") is not True:
        errs.append(f"ok={qr.get('ok')!r}")
    if qr.get("skip_count") != 0:
        errs.append(f"skip_count={qr.get('skip_count')!r}")
    if qr.get("ephemeral_state_retained") is not False:
        errs.append(f"ephemeral_state_retained={qr.get('ephemeral_state_retained')!r}")
    if qr.get("candidate_commit") != cand_commit:
        errs.append(f"commit mismatch: receipt={qr.get('candidate_commit')} bin={cand_commit}")
    if qr.get("qual_binary_sha256") != bin_sha:
        errs.append(f"binary sha256 mismatch: receipt={qr.get('qual_binary_sha256')} bin={bin_sha}")
    if errs:
        raise SystemExit("FAIL: --qualification-receipt validation failed: " + "; ".join(errs))
    bound_provenance = {
        "qualification_receipt": os.path.realpath(args.qualification_receipt),
        "manifest_sha256": qr.get("manifest_sha256", ""),
        "release_sequence": qr.get("release_sequence"),
        "signing_key_id": qr.get("signing_key_id", ""),
        "sbom_actual_sha256": qr.get("sbom_actual_sha256", ""),
    }

work = tempfile.mkdtemp(prefix="ocliv-soak-")
os.chmod(work, 0o700)
db_dir = os.path.join(work, "relay-data")
pub_home = os.path.join(work, "pub-home")
os.makedirs(db_dir, mode=0o700)
os.makedirs(pub_home, mode=0o700)

rport = pick_port()
hport = pick_port()
uport = pick_port()
base_url = f"http://127.0.0.1:{rport}"

up_srv = http.server.ThreadingHTTPServer(("127.0.0.1", uport), _UpstreamHandler)
threading.Thread(target=up_srv.serve_forever, daemon=True).start()

relay_log = open(os.path.join(work, "relay.log"), "w", encoding="utf-8")
pub_mcp_log = open(os.path.join(work, "pub-mcp.log"), "w", encoding="utf-8")
pub_http_log = open(os.path.join(work, "pub-http.log"), "w", encoding="utf-8")
relay = subprocess.Popen(
    [
        args.bin, "relay", "serve",
        f"--listen=127.0.0.1:{rport}",
        "--domain=soak.local",
        "--relay-host=127.0.0.1",
        "--data=" + db_dir,
        "--mcp-host=127.0.0.1",
        f"--mcp-port={rport}",
        f"--health-listen=127.0.0.1:{hport}",
    ],
    stdout=relay_log,
    stderr=subprocess.STDOUT,
)

pub_mcp_proc = None
pub_http_proc = None
pub_env = dict(os.environ)
pub_env["HOME"] = pub_home
pub_env["XDG_CONFIG_HOME"] = os.path.join(pub_home, ".config")
pub_env["OCLIV_RELAY_URL"] = base_url

counts = {
    "pair_attempted": 0, "pair_ok": 0, "pair_expected_429": 0, "pair_unexpected_fail": 0,
    "route_attempted": 0, "route_expected_401": 0, "route_unexpected_fail": 0,
    "dataplane_attempted": 0, "dataplane_ok_200": 0, "dataplane_unexpected_fail": 0,
    "disconnect_failed_as_expected": False, "reconnects_completed": 0,
}
tracker = PairingRecoveryTracker()
samples = []


def start_mcp_pub():
    return subprocess.Popen(
        [args.bin, "mcp", "publish", "--local", f"http://127.0.0.1:{uport}/mcp",
         "--auth", "ocliv-managed", "--name", "soak-pub", "--ttl", "30m", "--relay", base_url],
        stdout=pub_mcp_log, stderr=subprocess.STDOUT, env=pub_env,
    )


def start_http_pub():
    # Ad-hoc `ocliv PORT --public` leases do not auto-renew (unlike `mcp publish`),
    # so set TTL > soak duration to avoid planned expiry blips during multi-hour soaks.
    http_ttl_min = max(30, math.ceil((args.duration + 3600) / 60))
    return subprocess.Popen(
        [args.bin, str(uport), "--public", "--name", "soak-http", "--ttl", f"{http_ttl_min}m", "--relay", base_url],
        stdout=pub_http_log, stderr=subprocess.STDOUT, env=pub_env,
    )


def probe_dataplane(public_host, nonce):
    req = urllib.request.Request(
        f"{base_url}/soak-ping?nonce={nonce}",
        headers={"Host": public_host},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return -1, {}


def send_pair_request():
    pub_b64 = base64.b64encode(os.urandom(32)).decode()
    preq = urllib.request.Request(
        f"{base_url}/v1/agent/pair-request",
        data=json.dumps({"public_key": pub_b64}).encode(),
        headers={"Host": "127.0.0.1", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(preq, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1


failures = []
stats = {}
eff_warmup = min(warmup_sec, max(0, args.duration // 3))
eff_drain = min(drain_sec, max(0, args.duration // 3))
cleanup_ok = False
cleanup_err = ""

try:
    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{hport}/health/live", timeout=1).close()
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("soak relay failed to start")

    iss = subprocess.run([args.bin, "relay", "issue-enroll", "--data", db_dir, "--tenant", "soak-t"], capture_output=True, text=True)
    codes = [x for x in iss.stdout.split() if x.startswith("ocliv-enroll-")]
    if len(codes) != 1:
        raise RuntimeError("failed to mint soak enrollment code")
    code_file = os.path.join(work, "enroll.code")
    with open(code_file, "w", encoding="utf-8") as cf:
        cf.write(codes[0] + "\n")
    os.chmod(code_file, 0o600)
    login = subprocess.run([args.bin, "login", "--relay", base_url, "--code-file", code_file], capture_output=True, text=True, env=pub_env)
    os.remove(code_file)
    if login.returncode != 0:
        raise RuntimeError("soak publisher login failed: " + login.stderr)

    pol = subprocess.run([args.bin, "relay", "tenants", "policy", "set", "soak-t", "--allow-public=true", "--data", db_dir], capture_output=True, text=True)
    if pol.returncode != 0:
        raise RuntimeError("failed to enable allow_public on soak-t: " + pol.stderr)

    pub_mcp_proc = start_mcp_pub()
    pub_http_proc = start_http_pub()

    route_id = ""
    public_host = ""
    for _ in range(40):
        c = sqlite3.connect(f"file:{db_dir}/ocliv.db?mode=ro", uri=True)
        if not route_id:
            row = c.execute("SELECT route_id FROM mcp_publications WHERE pub_name='soak-pub' AND verified_at IS NOT NULL").fetchone()
            if row:
                route_id = row[0]
        if not public_host:
            row2 = c.execute("SELECT hostname FROM leases WHERE label='soak-http' AND status='ACTIVE' ORDER BY created_at DESC LIMIT 1").fetchone()
            if row2:
                public_host = row2[0]
        c.close()
        if route_id and public_host:
            break
        time.sleep(0.5)
    if not route_id or not public_host:
        raise RuntimeError(f"soak publishers did not register both lanes (route_id={route_id!r}, public_host={public_host!r})")

    start = time.time()
    drain_start_t = args.duration - eff_drain
    reconnected = False
    last_upstream_hit = 0
    expired_still_pending_end = 0

    while time.time() - start < args.duration:
        elapsed = time.time() - start
        in_drain = eff_drain > 0 and elapsed >= drain_start_t

        if not reconnected and elapsed >= max(3, (args.duration - eff_drain) / 2):
            pub_http_proc.terminate()
            pub_http_proc.wait(timeout=8)
            time.sleep(1)
            disc_st, _ = probe_dataplane(public_host, "disconnected-check")
            if disc_st != 200:
                counts["disconnect_failed_as_expected"] = True
            pub_http_proc = start_http_pub()
            for _ in range(40):
                st_r = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{hport}/health/status", timeout=2).read().decode())
                if st_r.get("active_sessions") == 2:
                    rec_nonce = f"rec-{int(time.time())}-{os.urandom(4).hex()}"
                    rst, rbody = probe_dataplane(public_host, rec_nonce)
                    if rst == 200 and rbody.get("soak_nonce") == rec_nonce:
                        counts["reconnects_completed"] += 1
                        last_upstream_hit = max(last_upstream_hit, int(rbody.get("upstream_hits", 0)))
                        break
                time.sleep(0.5)
            reconnected = True

        # 1. Lane 1: managed MCP route ingress (expects 401 unauthorized).
        counts["route_attempted"] += 1
        rreq = urllib.request.Request(
            f"{base_url}/r/{route_id}/mcp",
            data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            headers={"Host": f"127.0.0.1:{rport}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(rreq, timeout=5).close()
            counts["route_unexpected_fail"] += 1
        except urllib.error.HTTPError as e:
            if e.code == 401:
                counts["route_expected_401"] += 1
            else:
                counts["route_unexpected_fail"] += 1
        except Exception:
            counts["route_unexpected_fail"] += 1

        # 2. Lane 2: real end-to-end relay -> publisher -> upstream HTTP 200 with unique nonce.
        counts["dataplane_attempted"] += 1
        nonce = f"soak-{counts['dataplane_attempted']}-{os.urandom(6).hex()}"
        dp_st, dp_body = probe_dataplane(public_host, nonce)
        hit = int(dp_body.get("upstream_hits", 0)) if isinstance(dp_body, dict) else 0
        if dp_st == 200 and dp_body.get("soak_nonce") == nonce and hit > last_upstream_hit:
            counts["dataplane_ok_200"] += 1
            last_upstream_hit = hit
        else:
            counts["dataplane_unexpected_fail"] += 1

        # 3. Pairing request lifecycle with deterministic recovery state machine.
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if not in_drain:
            counts["pair_attempted"] += 1
            pst = send_pair_request()
            if pst == 200:
                counts["pair_ok"] += 1
                tracker.record(200, now_iso)
            elif pst == 429:
                counts["pair_expected_429"] += 1
                tracker.record(429, now_iso)
            else:
                counts["pair_unexpected_fail"] += 1

        st = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{hport}/health/status", timeout=3).read().decode())
        fd_count = len(os.listdir(f"/proc/{relay.pid}/fd"))
        rss_kb = 0
        with open(f"/proc/{relay.pid}/status", encoding="ascii") as sf:
            for line in sf:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
        wal_path = os.path.join(db_dir, "ocliv.db-wal")
        wal_bytes = os.path.getsize(wal_path) if os.path.exists(wal_path) else 0
        pc = sqlite3.connect(f"file:{db_dir}/ocliv.db?mode=ro", uri=True)
        pending_pairings = pc.execute("SELECT COUNT(*) FROM pairing_requests WHERE status='pending'").fetchone()[0]
        expired_still_pending_end = pc.execute(
            "SELECT COUNT(*) FROM pairing_requests WHERE status='pending' AND expires_at < ?", (now_iso,)
        ).fetchone()[0]
        pc.close()

        t_now = int(time.time() - start)
        sample = {
            "t": t_now,
            "in_warmup": t_now < eff_warmup,
            "in_drain": in_drain,
            "fds": fd_count,
            "rss_kb": rss_kb,
            "wal_bytes": wal_bytes,
            "pending_pairings": pending_pairings,
            "expired_still_pending": expired_still_pending_end,
            "process_ready": st.get("process_ready"),
            "active_sessions": st.get("active_sessions"),
        }
        samples.append(sample)
        print("SOAK_SAMPLE:", json.dumps(sample), flush=True)
        rem = args.duration - (time.time() - start)
        if rem > 0:
            time.sleep(min(args.sample_interval, max(1, int(rem))))

    # Final post-drain recovery probe if drain window was active or recovery is required.
    if eff_drain > 0 or tracker.recovery_required:
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        counts["pair_attempted"] += 1
        final_pst = send_pair_request()
        if final_pst == 200:
            counts["pair_ok"] += 1
            tracker.record(200, now_iso)
        elif final_pst == 429:
            counts["pair_expected_429"] += 1
            tracker.record(429, now_iso)
        else:
            counts["pair_unexpected_fail"] += 1

    post_warmup = [s for s in samples if not s["in_warmup"]] or samples
    base_n = min(3, len(post_warmup))
    fd_baseline = statistics.median([s["fds"] for s in post_warmup[:base_n]])
    rss_baseline = statistics.median([s["rss_kb"] for s in post_warmup[:base_n]])
    ts_post = [s["t"] for s in post_warmup]

    expected_active_pairings = math.ceil(PAIRING_TTL_SEC / max(1, args.sample_interval))
    allowed_pending_max = expected_active_pairings + 10

    window_comparison = {}
    if args.duration >= 21600 and len(post_warmup) >= 10:
        t0 = post_warmup[0]["t"]
        t_end = post_warmup[-1]["t"]
        first_hr = [s for s in post_warmup if s["t"] <= t0 + 3600]
        final_hr = [s for s in post_warmup if s["t"] >= t_end - 3600]
        if first_hr and final_hr:
            window_comparison = {
                "first_hour_fd_median": statistics.median([s["fds"] for s in first_hr]),
                "final_hour_fd_median": statistics.median([s["fds"] for s in final_hr]),
                "first_hour_rss_median": statistics.median([s["rss_kb"] for s in first_hr]),
                "final_hour_rss_median": statistics.median([s["rss_kb"] for s in final_hr]),
            }

    stats = {
        "warmup_sec": eff_warmup,
        "drain_sec": eff_drain,
        "post_warmup_samples": len(post_warmup),
        "fd_baseline": fd_baseline,
        "rss_kb_baseline": rss_baseline,
        "fds": series_stats([s["fds"] for s in post_warmup], ts_post),
        "rss_kb": series_stats([s["rss_kb"] for s in post_warmup], ts_post),
        "window_comparison": window_comparison,
        "wal_max_bytes": max(s["wal_bytes"] for s in samples) if samples else 0,
        "wal_end_bytes": samples[-1]["wal_bytes"] if samples else 0,
        "allowed_pending_max": allowed_pending_max,
        "pending_pairings_max": max(s["pending_pairings"] for s in samples) if samples else 0,
        "pending_pairings_end": samples[-1]["pending_pairings"] if samples else 0,
        "expired_still_pending_end": expired_still_pending_end,
    }

    if relay.poll() is not None:
        failures.append(f"relay exited prematurely (rc={relay.poll()})")
    if not samples or not all(s["process_ready"] for s in samples):
        failures.append("relay reported process_ready=False during soak")
    if counts["pair_unexpected_fail"] > 0 or counts["route_unexpected_fail"] > 0 or counts["dataplane_unexpected_fail"] > 0:
        failures.append(f"unexpected errors: {counts}")
    if counts["dataplane_ok_200"] < 1:
        failures.append("zero successful end-to-end relay->publisher->upstream HTTP 200 responses")
    if args.duration >= 6:
        if not counts["disconnect_failed_as_expected"]:
            failures.append("Lane 2 public route did not fail while publisher was disconnected")
        if counts["reconnects_completed"] < 1:
            failures.append("mid-soak publisher reconnect did not restore Lane 2 data plane")
    if samples and samples[-1]["active_sessions"] != 2:
        failures.append(f"final active_sessions={samples[-1]['active_sessions']}, want baseline 2")
    if tracker.recovery_required:
        failures.append(f"pairing limiter ended without post-429 recovery (last_429_at={tracker.last_429_at})")
    if stats["pending_pairings_max"] > allowed_pending_max:
        failures.append(f"pending_pairings exceeded derived bound: max={stats['pending_pairings_max']} > allowed={allowed_pending_max}")
    if eff_drain >= PAIRING_TTL_SEC:
        if expired_still_pending_end > 0:
            failures.append(f"drain failed: expired_still_pending={expired_still_pending_end} > 0")
        if stats["pending_pairings_end"] > 2:
            failures.append(f"drain failed: pending_pairings_end={stats['pending_pairings_end']} did not return near zero")
    if stats["fds"]["max"] > fd_baseline + 24:
        failures.append(f"FD growth exceeded bound: baseline={fd_baseline} max={stats['fds']['max']}")
    if stats["wal_max_bytes"] > 32 * 1024 * 1024:
        failures.append(f"WAL exceeded 32 MiB bound: max={stats['wal_max_bytes']}")
    if stats["rss_kb"]["max"] > rss_baseline * 2 + 32768:
        failures.append(f"RSS growth exceeded bound: baseline={rss_baseline}KB max={stats['rss_kb']['max']}KB")
    if window_comparison:
        if window_comparison["final_hour_fd_median"] > window_comparison["first_hour_fd_median"] + 8:
            failures.append(f"FD rolling-window growth: {window_comparison['first_hour_fd_median']} -> {window_comparison['final_hour_fd_median']}")
        if window_comparison["final_hour_rss_median"] > window_comparison["first_hour_rss_median"] * 1.5 + 32768:
            failures.append(f"RSS rolling-window growth: {window_comparison['first_hour_rss_median']}KB -> {window_comparison['final_hour_rss_median']}KB")
        if stats["fds"]["slope_per_hour"] > 0.5:
            failures.append(f"sustained positive FD slope: {stats['fds']['slope_per_hour']}/hr")
finally:
    for p in (pub_mcp_proc, pub_http_proc):
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    relay.terminate()
    try:
        relay.wait(timeout=8)
    except subprocess.TimeoutExpired:
        relay.kill()
    up_srv.shutdown()
    relay_log.close()
    pub_mcp_log.close()
    pub_http_log.close()
    # Fail-closed scratch cleanup: prove removal without ignore_errors BEFORE writing PASS receipt.
    try:
        shutil.rmtree(work)
        cleanup_ok = not os.path.exists(work)
    except Exception as exc:
        cleanup_ok = False
        cleanup_err = str(exc)

if not cleanup_ok:
    failures.append(f"fail-closed scratch cleanup failed for {work}: {cleanup_err}")

counts["pair_max_consecutive_429"] = tracker.max_consecutive_429
counts["saw_429"] = tracker.saw_429
counts["recovery_required_at_end"] = tracker.recovery_required
counts["recovery_events"] = tracker.recovery_events
counts["last_429_at"] = tracker.last_429_at
counts["last_recovery_at"] = tracker.last_recovery_at

receipt = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "release_gate": bool(args.release_gate),
    "candidate_commit": cand_commit,
    "binary_sha256": bin_sha,
    "schema_version": ver_info.get("schema_version"),
    "duration_sec": args.duration,
    "warmup_sec": eff_warmup,
    "drain_sec": eff_drain,
    "sample_interval_sec": args.sample_interval,
    "scratch_cleanup_ok": cleanup_ok,
    "scratch_retained": not cleanup_ok,
    "counts": counts,
    "stats": stats,
    "samples": samples,
    "failures": failures,
    "ok": (len(failures) == 0) and cleanup_ok,
}
receipt.update(bound_provenance)
if args.receipt_out:
    with open(args.receipt_out, "w", encoding="utf-8") as rf:
        json.dump(receipt, rf, indent=2)
if failures or not cleanup_ok:
    print("SOAK FAIL:", "; ".join(failures), file=sys.stderr)
    sys.exit(1)
print(
    f"SOAK PASS: samples={len(samples)} dataplane_200={counts['dataplane_ok_200']} "
    f"route_401={counts['route_expected_401']} reconnects={counts['reconnects_completed']} "
    f"pair_ok={counts['pair_ok']} FDs={stats['fds']['start']}->{stats['fds']['end']}(max={stats['fds']['max']}) "
    f"RSS={stats['rss_kb']['start']}KB->{stats['rss_kb']['end']}KB(max={stats['rss_kb']['max']}KB)"
)
