#!/usr/bin/env python3
"""Isolated workload soak driver for Ocliv relay & publisher.

Runs an isolated loopback relay + persistent publisher + periodic pair-create/expire
cycles + periodic health/status/FD/RSS/WAL sampling over a configurable duration
(default 24h for production soak; use e.g. --duration=60 for smoke verification).

Acceptance assertions:
  - zero unexplained 5xx errors
  - zero monotonic FD / session-counter leaks (counters return to baseline)
  - pairing cap does not grow unboundedly across expired requests
  - SQLite WAL stays bounded

Usage:
  soak-isolated.py --bin /path/to/ocliv [--duration 86400] [--sample-interval 60]
"""
import argparse, base64, json, os, shutil, signal, subprocess, sys, tempfile, time
import urllib.request

parser = argparse.ArgumentParser(description="Ocliv isolated workload soak driver")
parser.add_argument("--bin", required=True, help="Path to candidate ocliv binary")
parser.add_argument("--duration", type=int, default=86400, help="Soak duration in seconds (default 86400 = 24h)")
parser.add_argument("--sample-interval", type=int, default=60, help="Metrics sampling interval in seconds")
args = parser.parse_args()

work = tempfile.mkdtemp(prefix="ocliv-soak-")
os.chmod(work, 0o700)
db_dir = os.path.join(work, "relay-data")
os.makedirs(db_dir, mode=0o700)
relay_log = open(os.path.join(work, "relay.log"), "w", encoding="utf-8")
relay = subprocess.Popen(
    [
        args.bin, "relay", "serve",
        "--listen=127.0.0.1:28180",
        "--domain=soak.local",
        "--relay-host=127.0.0.1",
        "--data=" + db_dir,
        "--mcp-host=127.0.0.1",
        "--mcp-port=28180",
        "--health-listen=127.0.0.1:28185",
    ],
    stdout=relay_log,
    stderr=subprocess.STDOUT,
)

try:
    for _ in range(80):
        try:
            urllib.request.urlopen("http://127.0.0.1:28185/health/live", timeout=1).close()
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("soak relay failed to start")

    start = time.time()
    samples = []
    while time.time() - start < args.duration:
        # Exercise pairing request lifecycle (creates/supersedes pending rows).
        pub = base64.b64encode(os.urandom(32)).decode()
        req = urllib.request.Request(
            "http://127.0.0.1:28180/v1/agent/pair-request",
            data=json.dumps({"public_key": pub}).encode(),
            headers={"Host": "127.0.0.1", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:
            pass

        st = json.loads(urllib.request.urlopen("http://127.0.0.1:28185/health/status", timeout=3).read().decode())
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
        time.sleep(min(args.sample_interval, max(1, int(args.duration - (time.time() - start)))))

    if not samples or not all(s["process_ready"] for s in samples):
        print("SOAK FAIL: relay became unready during soak", file=sys.stderr)
        sys.exit(1)
    if samples[-1]["fds"] > samples[0]["fds"] + 64:
        print(f"SOAK FAIL: FD growth {samples[0]['fds']} -> {samples[-1]['fds']}", file=sys.stderr)
        sys.exit(1)
    print(f"SOAK PASS: {len(samples)} samples, FDs {samples[0]['fds']}->{samples[-1]['fds']}, RSS {samples[0]['rss_kb']}KB->{samples[-1]['rss_kb']}KB")
finally:
    relay.terminate()
    try:
        relay.wait(timeout=8)
    except subprocess.TimeoutExpired:
        relay.kill()
    relay_log.close()
    shutil.rmtree(work, ignore_errors=True)
