#!/usr/bin/env bash
set -euo pipefail

# 24-hour MCP availability/reconnect soak. The caller supplies a harmless
# tool and an isolated-relay drop hook that waits for lease expiry and
# reports the old/new lease IDs. A run without reclaim evidence is not a
# qualification pass. This script never changes a production relay or
# chooses a tool on its own.

need() { [[ -n "${!1:-}" ]] || { echo "missing required environment variable: $1" >&2; exit 2; }; }
need OCLIV_SOAK_URL
need OCLIV_SOAK_BEARER_FILE
need OCLIV_SOAK_TOOL
need OCLIV_SOAK_PIDS
need OCLIV_SOAK_DROP_HOOK
[[ -r "$OCLIV_SOAK_BEARER_FILE" ]] || { echo "bearer file is not readable" >&2; exit 2; }

duration="${OCLIV_SOAK_DURATION_SECONDS:-86400}"
interval="${OCLIV_SOAK_INTERVAL_SECONDS:-30}"
drop_every="${OCLIV_SOAK_DROP_EVERY_SECONDS:-3600}"
max_rss_growth="${OCLIV_SOAK_MAX_RSS_GROWTH_KB:-65536}"
drop_timeout="${OCLIV_SOAK_DROP_TIMEOUT_SECONDS:-43200}"
args_json="${OCLIV_SOAK_ARGS_JSON:-{}}"
drop_hook="$OCLIV_SOAK_DROP_HOOK"

for value in "$duration" "$interval" "$drop_every" "$max_rss_growth" "$drop_timeout"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { echo "duration, interval, drop cadence, and RSS limit must be integers" >&2; exit 2; }
done
(( duration > 0 && interval > 0 && drop_every > 0 )) || { echo "duration and intervals must be positive" >&2; exit 2; }
[[ "${OCLIV_SOAK_ISOLATED_RELAY:-}" == "YES" ]] || {
  echo "lease-reclaim hooks require OCLIV_SOAK_ISOLATED_RELAY=YES; never point them at production" >&2
  exit 2
}
[[ -x "$drop_hook" ]] || { echo "drop hook must be an executable file" >&2; exit 2; }

export OCLIV_SOAK_URL OCLIV_SOAK_BEARER_FILE OCLIV_SOAK_TOOL OCLIV_SOAK_ARGS_JSON="$args_json"
export OCLIV_SOAK_DURATION_SECONDS="$duration" OCLIV_SOAK_INTERVAL_SECONDS="$interval"
export OCLIV_SOAK_DROP_EVERY_SECONDS="$drop_every" OCLIV_SOAK_MAX_RSS_GROWTH_KB="$max_rss_growth"
export OCLIV_SOAK_DROP_TIMEOUT_SECONDS="$drop_timeout"
export OCLIV_SOAK_DROP_HOOK="$drop_hook"

python3 - <<'PY'
import json, os, pathlib, subprocess, sys, time, urllib.error, urllib.request

url = os.environ["OCLIV_SOAK_URL"]
token_path = pathlib.Path(os.environ["OCLIV_SOAK_BEARER_FILE"])
if token_path.stat().st_mode & 0o077:
    raise SystemExit("bearer file must be owner-only (mode 0600)")
tool = os.environ["OCLIV_SOAK_TOOL"]
args = json.loads(os.environ["OCLIV_SOAK_ARGS_JSON"])
duration = int(os.environ["OCLIV_SOAK_DURATION_SECONDS"])
interval = int(os.environ["OCLIV_SOAK_INTERVAL_SECONDS"])
drop_every = int(os.environ["OCLIV_SOAK_DROP_EVERY_SECONDS"])
max_growth = int(os.environ["OCLIV_SOAK_MAX_RSS_GROWTH_KB"])
drop_timeout = int(os.environ["OCLIV_SOAK_DROP_TIMEOUT_SECONDS"])
drop_hook = os.environ["OCLIV_SOAK_DROP_HOOK"]
if not url.startswith("https://"):
    raise SystemExit("OCLIV_SOAK_URL must use HTTPS")
if not isinstance(args, dict):
    raise SystemExit("OCLIV_SOAK_ARGS_JSON must be a JSON object")
if not token:
    raise SystemExit("bearer file is empty")

session = None
rpc_id = 0

def request(method, params=None, notification=False):
    global session, rpc_id
    rpc_id += 1
    token = token_path.read_text().strip()
    if not token:
        raise RuntimeError("bearer file is empty")
    msg = {"jsonrpc": "2.0", "method": method}
    if not notification:
        msg["id"] = rpc_id
    if params is not None:
        msg["params"] = params
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-11-25",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(msg).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status != 200:
                raise RuntimeError("HTTP " + str(resp.status))
            session = resp.headers.get("Mcp-Session-Id", session)
            raw = resp.read().decode("utf-8", "replace")
            ctype = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        raise RuntimeError("HTTP " + str(e.code) + ": " + e.read(1024).decode("utf-8", "replace"))
    if notification:
        return None
    if "text/event-stream" in ctype:
        payloads = [line[6:].strip() for line in raw.splitlines() if line.startswith("data: ")]
        for payload in reversed(payloads):
            try:
                value = json.loads(payload)
                if "id" in value:
                    return value
            except json.JSONDecodeError:
                pass
        raise RuntimeError("SSE response contained no JSON-RPC result")
    return json.loads(raw)

def rpc_result(message):
    if "error" in message:
        raise RuntimeError("JSON-RPC error: " + json.dumps(message["error"]))
    return message.get("result", {})

def cycle():
    global session
    if not session:
        init = request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                        "clientInfo": {"name": "ocliv-soak", "version": "1"}})
        rpc_result(init)
        request("notifications/initialized", notification=True)
    listing = rpc_result(request("tools/list"))
    names = {item.get("name") for item in listing.get("tools", [])}
    if tool not in names:
        raise RuntimeError("tools/list did not advertise configured harmless tool " + repr(tool))
    call = rpc_result(request("tools/call", {"name": tool, "arguments": args}))
    if call.get("isError"):
        raise RuntimeError("tools/call returned isError: " + json.dumps(call))

def rss_kb():
    values = []
    for pid in filter(None, os.environ.get("OCLIV_SOAK_PIDS", "").split(",")):
        status = pathlib.Path("/proc", pid.strip(), "status")
        try:
            for line in status.read_text().splitlines():
                if line.startswith("VmRSS:"):
                    values.append(int(line.split()[1]))
                    break
        except (OSError, ValueError):
            raise RuntimeError("configured soak process disappeared: " + pid)
    if not values:
        raise RuntimeError("OCLIV_SOAK_PIDS must contain at least one Linux process ID")
    return sum(values)

baseline = rss_kb()
max_seen = baseline
started = time.monotonic()
next_drop = started + drop_every
cycles = 0
while time.monotonic() - started < duration:
    cycle()
    cycles += 1
    current_rss = rss_kb()
    max_seen = max(max_seen, current_rss)
    if current_rss - baseline > max_growth:
        raise SystemExit("RSS growth exceeded limit: baseline=%dKiB current=%dKiB limit=%dKiB" %
                         (baseline, current_rss, max_growth))
    now = time.monotonic()
    if now >= next_drop:
        result = subprocess.run([drop_hook, url], check=True, capture_output=True, text=True, timeout=drop_timeout)
        evidence = json.loads(result.stdout)
        if evidence.get("route_url") != url:
            raise SystemExit("reconnect changed route URL: " + repr(evidence.get("route_url")))
        if not evidence.get("old_lease") or not evidence.get("new_lease") or evidence["old_lease"] == evidence["new_lease"]:
            raise SystemExit("drop hook did not prove L1 -> L2 lease reclaim: " + json.dumps(evidence))
        session = None
        cycle()
        cycles += 1
        print("lease reclaim verified: %s -> %s; route unchanged" % (evidence["old_lease"], evidence["new_lease"]), flush=True)
        next_drop = time.monotonic() + drop_every
    if cycles == 1 or cycles % max(1, 3600 // interval) == 0:
        print("soak ok: cycles=%d elapsed=%ds rss=%dKiB peak=%dKiB" %
              (cycles, int(time.monotonic() - started), current_rss, max_seen), flush=True)
    time.sleep(min(interval, max(0, duration - (time.monotonic() - started))))

print("SOAK PASS: cycles=%d duration=%ds rss_baseline=%dKiB rss_peak=%dKiB" %
      (cycles, duration, baseline, max_seen))
PY
