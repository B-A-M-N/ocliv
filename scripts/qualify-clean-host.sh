#!/usr/bin/env bash
set -euo pipefail

# End-to-end publisher lifecycle check for a disposable clean Ubuntu host.
# The relay and local MCP server are explicit inputs; this script never
# installs or changes a relay edge. Use a dedicated qualification relay.

need() { [[ -n "${!1:-}" ]] || { echo "missing required environment variable: $1" >&2; exit 2; }; }
need OCLIV_QUALIFY_RELAY
need OCLIV_QUALIFY_ENROLL_CODE_FILE
need OCLIV_QUALIFY_UPSTREAM_TOKEN_FILE
need OCLIV_QUALIFY_PUBLIC_TOKEN_FILE
need OCLIV_QUALIFY_TOOL
need OCLIV_QUALIFY_LOCAL_MCP_URL
need OCLIV_QUALIFY_RESOURCE_FILE
[[ "${OCLIV_QUALIFY_ISOLATED_RELAY:-}" == "YES" ]] || {
  echo "refusing route mutations without OCLIV_QUALIFY_ISOLATED_RELAY=YES" >&2; exit 2;
}
for f in "$OCLIV_QUALIFY_ENROLL_CODE_FILE" "$OCLIV_QUALIFY_UPSTREAM_TOKEN_FILE" "$OCLIV_QUALIFY_PUBLIC_TOKEN_FILE"; do
  [[ -r "$f" ]] || { echo "required credential file is unreadable: $f" >&2; exit 2; }
done
python3 - "$OCLIV_QUALIFY_UPSTREAM_TOKEN_FILE" "$OCLIV_QUALIFY_PUBLIC_TOKEN_FILE" <<'PY'
import os, sys
for path in sys.argv[1:]:
    if os.stat(path).st_mode & 0o077:
        raise SystemExit("credential file must be owner-only (mode 0600): " + path)
PY

work="$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/ocliv-clean-qual.XXXXXX")"
publisher_pid=""
cleanup() {
  if [[ -n "$publisher_pid" ]] && kill -0 "$publisher_pid" 2>/dev/null; then
    kill -TERM "$publisher_pid" 2>/dev/null || true
    wait "$publisher_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir -p "$HOME/.local/bin"
if [[ -n "${OCLIV_QUALIFY_OCLIV_BIN:-}" ]]; then
  install -m 0755 "$OCLIV_QUALIFY_OCLIV_BIN" "$HOME/.local/bin/ocliv"
fi
if [[ -n "${OCLIV_QUALIFY_CADDY_BIN:-}" ]]; then
  install -m 0755 "$OCLIV_QUALIFY_CADDY_BIN" "$HOME/.local/bin/caddy"
fi
if [[ -n "${OCLIV_QUALIFY_AGENTGATEWAY_BIN:-}" ]]; then
  install -m 0755 "$OCLIV_QUALIFY_AGENTGATEWAY_BIN" "$HOME/.local/bin/agentgateway"
fi
export PATH="$HOME/.local/bin:$PATH"
command -v ocliv >/dev/null || { echo "ocliv is not installed; set OCLIV_QUALIFY_OCLIV_BIN" >&2; exit 2; }
command -v caddy >/dev/null || { echo "Caddy is not installed; set OCLIV_QUALIFY_CADDY_BIN" >&2; exit 2; }
command -v agentgateway >/dev/null || { echo "agentgateway is not installed; set OCLIV_QUALIFY_AGENTGATEWAY_BIN" >&2; exit 2; }
[[ -r "$OCLIV_QUALIFY_PUBLIC_TOKEN_FILE" && -r "$OCLIV_QUALIFY_UPSTREAM_TOKEN_FILE" ]]

ocliv setup --check
cat "$OCLIV_QUALIFY_ENROLL_CODE_FILE" | ocliv login --relay "$OCLIV_QUALIFY_RELAY" --code-file -

name="${OCLIV_QUALIFY_PUBLICATION_NAME:-clean-host-canary}"
start_publisher() {
  OCLIV_UPSTREAM_MCP_TOKEN="$(cat "$OCLIV_QUALIFY_UPSTREAM_TOKEN_FILE")" \
    ocliv mcp publish --local "$OCLIV_QUALIFY_LOCAL_MCP_URL" --auth upstream-oauth --name "$name" \
      --resource-file "$OCLIV_QUALIFY_RESOURCE_FILE" --strict-discovery \
    >"$work/publisher.log" 2>&1 &
  publisher_pid=$!
}
wait_for_url() {
  for _ in $(seq 1 120); do
    route="$(python3 - "$work/publisher.log" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(errors="replace")
matches = re.findall(r"https://[^\s]+/r/[A-Za-z0-9_-]+/mcp", text)
print(matches[-1] if matches else "")
PY
)"
    [[ -n "$route" ]] && { printf '%s\n' "$route"; return 0; }
    if ! kill -0 "$publisher_pid" 2>/dev/null; then
      cat "$work/publisher.log" >&2
      echo "publisher exited before publishing" >&2
      return 1
    fi
    sleep 1
  done
  cat "$work/publisher.log" >&2
  echo "timed out waiting for publication URL" >&2
  return 1
}

probe() {
  local want="$1" route="$2"
  OCLIV_PROBE_URL="$route" OCLIV_PROBE_EXPECT="$want" \
  OCLIV_PROBE_TOKEN_FILE="$OCLIV_QUALIFY_PUBLIC_TOKEN_FILE" \
  OCLIV_PROBE_TOOL="$OCLIV_QUALIFY_TOOL" OCLIV_PROBE_ARGS="${OCLIV_QUALIFY_TOOL_ARGS_JSON:-{}}" \
  python3 - <<'PY'
import json, os, pathlib, urllib.error, urllib.request
url, want = os.environ["OCLIV_PROBE_URL"], int(os.environ["OCLIV_PROBE_EXPECT"])
token = pathlib.Path(os.environ["OCLIV_PROBE_TOKEN_FILE"]).read_text().strip()
tool, args = os.environ["OCLIV_PROBE_TOOL"], json.loads(os.environ["OCLIV_PROBE_ARGS"])
sid = None
seq = 0
def post(method, params=None, notification=False):
    global sid, seq
    seq += 1
    msg = {"jsonrpc":"2.0", "method":method}
    if not notification: msg["id"] = seq
    if params is not None: msg["params"] = params
    headers = {"Authorization":"Bearer " + token, "Accept":"application/json, text/event-stream",
               "Content-Type":"application/json", "MCP-Protocol-Version":"2025-11-25"}
    if sid: headers["Mcp-Session-Id"] = sid
    req = urllib.request.Request(url, data=json.dumps(msg).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, raw, ctype = resp.status, resp.read().decode(errors="replace"), resp.headers.get("Content-Type", "")
            sid = resp.headers.get("Mcp-Session-Id", sid)
    except urllib.error.HTTPError as e:
        status, raw, ctype = e.code, e.read(1024).decode(errors="replace"), ""
    if status != want:
        raise SystemExit("expected HTTP %d, got %d: %s" % (want, status, raw[:300]))
    if status != 200 or notification: return None
    if "text/event-stream" in ctype:
        values = [line[6:].strip() for line in raw.splitlines() if line.startswith("data: ")]
        for value in reversed(values):
            try:
                obj = json.loads(value)
                if "id" in obj: return obj
            except json.JSONDecodeError: pass
        raise SystemExit("SSE response had no JSON-RPC result")
    return json.loads(raw)
if want != 200:
    post("tools/list", {})
else:
    initialized = post("initialize", {"protocolVersion":"2025-11-25", "capabilities":{},
                                       "clientInfo":{"name":"ocliv-clean-host-qualification", "version":"1"}})
    if "error" in initialized: raise SystemExit("initialize failed: " + json.dumps(initialized["error"]))
    post("notifications/initialized", notification=True)
    listing = post("tools/list", {})
    if "error" in listing: raise SystemExit("tools/list failed: " + json.dumps(listing["error"]))
    names = {x.get("name") for x in listing.get("result", {}).get("tools", [])}
    if tool not in names: raise SystemExit("configured harmless tool missing from tools/list: " + tool)
    called = post("tools/call", {"name":tool, "arguments":args})
    result = called.get("result", {})
    if "error" in called or result.get("isError"):
        raise SystemExit("harmless tools/call failed: " + json.dumps(called))
print("HTTP %d MCP probe passed" % want)
PY
}

start_publisher
route="$(wait_for_url)"
probe 200 "$route"
echo "published: $route"

kill -TERM "$publisher_pid"
wait "$publisher_pid" || true
publisher_pid=""
probe 503 "$route"
echo "pause: same route returns 503"

start_publisher
resumed="$(wait_for_url)"
[[ "$resumed" == "$route" ]] || { echo "resume changed URL: $route -> $resumed" >&2; exit 1; }
probe 200 "$resumed"
echo "resume: same route returned to HTTP 200"

ocliv mcp revoke --name "$name"
probe 404 "$route"
kill -TERM "$publisher_pid" 2>/dev/null || true
wait "$publisher_pid" 2>/dev/null || true
publisher_pid=""
echo "CLEAN-HOST PASS: publish, pause, same-URL resume, and permanent revoke verified"
