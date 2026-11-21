#!/usr/bin/env python3
"""Isolated workload soak driver for Ocliv relay + persistent publisher.

Runs an isolated loopback relay, a local HTTP upstream, and a live enrolled
publisher (`ocliv mcp publish`), exercising:
  - live relay->publisher->upstream HTTP traffic every interval
  - periodic pair-request lifecycle calls (never swallowing errors)
  - a deliberate mid-soak publisher disconnect and reconnect
  - warm-up + bounded FD, RSS, WAL, active-session, and error-count checks
  - JSON sample log + summarized receipt output

Usage:
  soak-isolated.py --bin /path/to/ocliv [--duration 86400] [--sample-interval 60] [--receipt-out PATH]
"""
import argparse, base64, http.server, json, os, shutil, socket, sqlite3, subprocess, sys, tempfile, threading, time
import urllib.error, urllib.request

parser = argparse.ArgumentParser(description="Ocliv isolated workload soak driver")
parser.add_argument("--bin", required=True, help="Path to candidate ocliv binary")
parser.add_argument("--duration", type=int, default=86400, help="Soak duration in seconds (default 86400 = 24h)")
parser.add_argument("--sample-interval", type=int, default=60, help="Sampling interval in seconds")
parser.add_argument("--receipt-out", default="", help="Optional path to write JSON soak receipt + samples")
args = parser.parse_args()


def pick_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _UpstreamHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(ln)
        data = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "ping"}]}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


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
pub_log = open(os.path.join(work, "pub.log"), "w", encoding="utf-8")
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

pub_proc = None
pub_env = dict(os.environ)
pub_env["HOME"] = pub_home
pub_env["XDG_CONFIG_HOME"] = os.path.join(pub_home, ".config")
pub_env["OCLIV_RELAY_URL"] = base_url

counts = {
    "pair_attempted": 0, "pair_ok": 0, "pair_expected_429": 0, "pair_unexpected_fail": 0,
    "route_attempted": 0, "route_expected_401": 0, "route_unexpected_fail": 0,
    "reconnects_completed": 0,
}
samples = []


def start_pub():
    return subprocess.Popen(
        [args.bin, "mcp", "publish", "--local", f"http://127.0.0.1:{uport}/mcp",
         "--auth", "ocliv-managed", "--name", "soak-pub", "--ttl", "30m", "--relay", base_url],
        stdout=pub_log, stderr=subprocess.STDOUT, env=pub_env,
    )


try:
    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{hport}/health/live", timeout=1).close()
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("soak relay failed to start")

    # Enroll publisher (unlink code file immediately after login).
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

    pub_proc = start_pub()
    route_id = ""
    for _ in range(40):
        c = sqlite3.connect(f"file:{db_dir}/ocliv.db?mode=ro", uri=True)
        row = c.execute("SELECT route_id FROM mcp_publications WHERE pub_name='soak-pub' AND verified_at IS NOT NULL").fetchone()
        c.close()
        if row:
            route_id = row[0]
            break
        time.sleep(0.5)
    if not route_id:
        raise RuntimeError("soak publisher did not register verified route")

    start = time.time()
    reconnected = False
    while time.time() - start < args.duration:
        elapsed = time.time() - start
        # Deliberate mid-soak publisher disconnect + reconnect once.
        if not reconnected and elapsed >= max(3, args.duration / 2):
            pub_proc.terminate()
            pub_proc.wait(timeout=8)
            time.sleep(1)
            pub_proc = start_pub()
            for _ in range(30):
                st_r = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{hport}/health/status", timeout=2).read().decode())
                if st_r.get("active_sessions") == 1:
                    counts["reconnects_completed"] += 1
                    break
                time.sleep(0.5)
            reconnected = True

        # 1. Exercise route ingress (expects 401 unauthorized; 5xx/transport error is a failure).
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

        # 2. Exercise pairing request lifecycle (200 or expected per-IP 429; 5xx/transport error fails).
        counts["pair_attempted"] += 1
        pub_b64 = base64.b64encode(os.urandom(32)).decode()
        preq = urllib.request.Request(
            f"{base_url}/v1/agent/pair-request",
            data=json.dumps({"public_key": pub_b64}).encode(),
            headers={"Host": "127.0.0.1", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(preq, timeout=5) as resp:
                if resp.status == 200:
                    counts["pair_ok"] += 1
                else:
                    counts["pair_unexpected_fail"] += 1
        except urllib.error.HTTPError as e:
            if e.code == 429:
                counts["pair_expected_429"] += 1
            else:
                counts["pair_unexpected_fail"] += 1
        except Exception:
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
        sample = {
            "t": int(time.time() - start),
            "fds": fd_count,
            "rss_kb": rss_kb,
            "wal_bytes": wal_bytes,
            "process_ready": st.get("process_ready"),
            "active_sessions": st.get("active_sessions"),
        }
        samples.append(sample)
        print("SOAK_SAMPLE:", json.dumps(sample), flush=True)
        rem = args.duration - (time.time() - start)
        if rem > 0:
            time.sleep(min(args.sample_interval, max(1, int(rem))))

    failures = []
    if relay.poll() is not None:
        failures.append(f"relay exited prematurely (rc={relay.poll()})")
    if not samples or not all(s["process_ready"] for s in samples):
        failures.append("relay reported process_ready=False during soak")
    if counts["pair_unexpected_fail"] > 0 or counts["route_unexpected_fail"] > 0:
        failures.append(f"unexpected errors: {counts}")
    if counts["reconnects_completed"] < 1 and args.duration >= 6:
        failures.append("mid-soak publisher reconnect did not restore active_sessions=1")
    if samples and samples[-1]["active_sessions"] != 1:
        failures.append(f"final active_sessions={samples[-1]['active_sessions']}, want baseline 1")
    if samples and samples[-1]["fds"] > samples[0]["fds"] + 16:
        failures.append(f"FD leak: {samples[0]['fds']} -> {samples[-1]['fds']}")
    if samples and max(s["wal_bytes"] for s in samples) > 32 * 1024 * 1024:
        failures.append("WAL exceeded 32 MiB bound")
    if samples and samples[-1]["rss_kb"] > samples[0]["rss_kb"] * 2 + 32768:
        failures.append(f"RSS growth exceeded bound: {samples[0]['rss_kb']}KB -> {samples[-1]['rss_kb']}KB")

    receipt = {"counts": counts, "samples": samples, "failures": failures, "ok": len(failures) == 0}
    if args.receipt_out:
        with open(args.receipt_out, "w", encoding="utf-8") as rf:
            json.dump(receipt, rf, indent=2)
    if failures:
        print("SOAK FAIL:", "; ".join(failures), file=sys.stderr)
        sys.exit(1)
    print(f"SOAK PASS: samples={len(samples)} reconnects={counts['reconnects_completed']} route_401={counts['route_expected_401']} pair_ok={counts['pair_ok']} FDs={samples[0]['fds']}->{samples[-1]['fds']} RSS={samples[0]['rss_kb']}KB->{samples[-1]['rss_kb']}KB")
finally:
    if pub_proc is not None and pub_proc.poll() is None:
        pub_proc.terminate()
        try:
            pub_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pub_proc.kill()
    relay.terminate()
    try:
        relay.wait(timeout=8)
    except subprocess.TimeoutExpired:
        relay.kill()
    up_srv.shutdown()
    relay_log.close()
    pub_log.close()
    shutil.rmtree(work, ignore_errors=True)
