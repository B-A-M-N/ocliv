#!/bin/sh
# Build the ChatGPT plugin ZIP.
# Usage: ./build-plugin.sh [--release] [out-dir]
#
# plugin/mcp.json ships a clearly-labeled REPLACE-WITH-* development
# template URL (see plugin/README.md). A --release build requires the
# exact operator-qualified endpoint through OCLIV_QUALIFIED_MCP_URL.
set -eu
cd "$(dirname "$0")"

RELEASE=0
if [ "${1:-}" = "--release" ]; then
  RELEASE=1
  shift
fi
OUT="${1:-./dist}"

case "$OUT" in
  /*) ABS_OUT="$OUT" ;;
  *) ABS_OUT="$(pwd)/$OUT" ;;
esac

python3 - "$RELEASE" <<'EOF'
import datetime, json, os, re, subprocess, sys
from urllib.parse import urlsplit

release = sys.argv[1] == "1"
failures = []
def fail(msg):
    failures.append(msg)

def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        fail("%s: invalid JSON: %s" % (path, e))
        return None

PLUGIN_SRC="../../integrations/chatgpt-plugin"
plugin = load(PLUGIN_SRC + "/plugin.json")
mcp = load(PLUGIN_SRC + "/mcp.json")

# --- plugin.json identity ---
if plugin is not None:
    if plugin.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json":
        fail("plugin.json: unexpected $schema %r" % plugin.get("$schema"))
    if plugin.get("name") != "ocliv-chatgpt-hosting":
        fail("plugin.json: name must be 'ocliv-chatgpt-hosting', got %r" % plugin.get("name"))
    ver = plugin.get("version", "")
    if not re.match(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$", str(ver)):
        fail("plugin.json: version %r is not SemVer" % ver)
    else:
        nums = [int(x) for x in str(ver).split("-")[0].split(".")]
        if nums < [0, 1, 2]:
            fail("plugin.json: version %r is a downgrade below 0.1.2" % ver)
    if not plugin.get("description"):
        fail("plugin.json: description must be nonempty")

# --- mcp.json connection ---
if mcp is not None:
    if mcp.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json":
        fail("mcp.json: unexpected $schema %r" % mcp.get("$schema"))
    servers = mcp.get("mcpServers")
    entry = servers.get("ocliv") if isinstance(servers, dict) else None
    if not isinstance(entry, dict):
        fail("mcp.json: mcpServers.ocliv entry missing")
    else:
        if entry.get("type") != "streamable-http":
            fail("mcp.json: mcpServers.ocliv.type must be 'streamable-http', got %r" % entry.get("type"))
        url = os.environ.get("OCLIV_QUALIFIED_MCP_URL", "") if release else entry.get("url", "")
        if not isinstance(url, str) or not url:
            fail("mcp.json: release requires OCLIV_QUALIFIED_MCP_URL; dev builds require a nonempty template URL")
        else:
            if "relay.ocliv.test" in url or "ocliv.test" in url:
                fail("mcp.json: url points at a lab host (ocliv.test); release and dev builds must never bake it in")
            if re.search(r"https?://(localhost|127\.|0\.0\.0\.0|\[::1\])", url):
                fail("mcp.json: url points at loopback; it must never be baked into a plugin ZIP")
            if "REPLACE-WITH-" in url:
                if release:
                    fail("mcp.json: unresolved development-template placeholder; --release needs the qualified live route URL")
                else:
                    print("warning: dev build keeps the REPLACE-WITH-* template URL (not a release artifact)")
            elif not url.startswith("https://"):
                fail("mcp.json: url must use https, got %r" % url)
            elif release:
                host = (urlsplit(url).hostname or "").lower()
                if host == "pop-os.tail8d285a.ts.net":
                    fail("mcp.json: retired Ocliv Funnel host is offline; release URL must use a currently qualified public endpoint")
                if not re.match(r"^https://[^/]+/r/[^/]+/mcp$", url):
                    fail("mcp.json: OCLIV_QUALIFIED_MCP_URL must be an exact HTTPS /r/<route-id>/mcp endpoint")
                receipt_path = os.environ.get("OCLIV_MCP_QUALIFICATION_RECEIPT", "")
                verify_key = os.environ.get("OCLIV_RECEIPT_VERIFY_KEY", "")
                expected_revision = os.environ.get("OCLIV_SOURCE_REVISION", "")
                expected_digest = os.environ.get("OCLIV_ARTIFACT_SHA256", "").lower()
                if not receipt_path:
                    fail("mcp.json: release requires OCLIV_MCP_QUALIFICATION_RECEIPT from verify-ingress.sh")
                if not verify_key or not expected_revision or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
                    fail("release requires OCLIV_RECEIPT_VERIFY_KEY, OCLIV_SOURCE_REVISION, and a 64-hex OCLIV_ARTIFACT_SHA256")
                else:
                    try:
                        subprocess.run(["openssl", "dgst", "-sha256", "-verify", verify_key,
                                        "-signature", receipt_path + ".sig", receipt_path],
                                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                        with open(receipt_path, encoding="utf-8") as f:
                            receipt = json.load(f)
                        checked = datetime.datetime.fromisoformat(receipt["checked_at"].replace("Z", "+00:00"))
                        age = (datetime.datetime.now(datetime.timezone.utc) - checked).total_seconds()
                        if receipt.get("route_url") != url:
                            fail("qualification receipt URL does not match OCLIV_QUALIFIED_MCP_URL")
                        if receipt.get("source_revision") != expected_revision:
                            fail("qualification receipt source revision does not match OCLIV_SOURCE_REVISION")
                        if receipt.get("artifact_sha256") != expected_digest:
                            fail("qualification receipt artifact digest does not match OCLIV_ARTIFACT_SHA256")
                        if not 0 <= age <= 3600:
                            fail("qualification receipt must be no more than one hour old")
                        for key in ("resource_discovery_verified", "authorization_server_discovery_verified", "missing_bearer_rejected", "invalid_bearer_rejected", "authenticated_tools_list_verified", "authenticated_tool_execution_verified"):
                            if receipt.get(key) is not True:
                                fail("qualification receipt lacks required result: %s" % key)
                    except Exception as e:
                        fail("cannot verify signed OCLIV_MCP_QUALIFICATION_RECEIPT: %s" % e)

# --- skill frontmatter ---
try:
    with open("../../integrations/chatgpt-plugin/skills/setup/SKILL.md", encoding="utf-8") as f:
        skill = f.read()
except OSError as e:
    fail("skills/setup/SKILL.md: unreadable: %s" % e)
    skill = None
if skill is not None:
    if not skill.startswith("---\n"):
        fail("skills/setup/SKILL.md: missing YAML frontmatter (must start with '---')")
    else:
        end = skill.find("\n---", 4)
        if end < 0:
            fail("skills/setup/SKILL.md: unterminated YAML frontmatter")
        else:
            fm = skill[4:end]
            if not re.search(r"(?m)^name:\s*setup\s*$", fm):
                fail("skills/setup/SKILL.md: frontmatter must declare 'name: setup'")
            m = re.search(r"(?m)^description:\s*(.+?)\s*$", fm)
            if not m or not m.group(1).strip():
                fail("skills/setup/SKILL.md: frontmatter must declare a nonempty 'description:'")

if failures:
    for msg in failures:
        print("error: %s" % msg)
    sys.exit(1)
print("manifest validation OK (release=%s)" % ("yes" if release else "no"))
EOF

# --- relative layout: expected files, no absolute paths ---
PLUGIN_SRC="../../integrations/chatgpt-plugin"
for f in plugin.json mcp.json README.md skills/setup/SKILL.md; do
  [ -f "$PLUGIN_SRC/$f" ] || { echo "error: $PLUGIN_SRC/$f missing" >&2; exit 1; }
done

mkdir -p "$ABS_OUT"
rm -f "$ABS_OUT/ocliv-chatgpt-plugin.zip"
EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
rm -rf stage-plugin && cp -r "$PLUGIN_SRC" stage-plugin
if [ "$RELEASE" = 1 ]; then
  python3 - "$OCLIV_QUALIFIED_MCP_URL" <<'EOF'
import json, sys
path = "stage-plugin/mcp.json"
with open(path, encoding="utf-8") as f:
    manifest = json.load(f)
manifest["mcpServers"]["ocliv"]["url"] = sys.argv[1]
with open(path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
EOF
fi
find stage-plugin -exec touch -h -d "@$EPOCH" {} +
(cd stage-plugin && find . -type f | LC_ALL=C sort | zip -X -9 -q -@ "$ABS_OUT/ocliv-chatgpt-plugin.zip")
rm -rf stage-plugin
(cd "$ABS_OUT" && sha256sum ocliv-chatgpt-plugin.zip > SHA256SUMS.tmp \
  && { [ ! -f SHA256SUMS ] || grep -v ' ocliv-chatgpt-plugin\.zip$' SHA256SUMS > SHA256SUMS.keep || true; } \
  && cat SHA256SUMS.tmp >> SHA256SUMS.keep && mv SHA256SUMS.keep SHA256SUMS && rm SHA256SUMS.tmp)
unzip -l "$ABS_OUT/ocliv-chatgpt-plugin.zip"
