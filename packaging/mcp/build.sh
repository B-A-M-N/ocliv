#!/bin/sh
# Build the reproducible Ocliv MCP runtime ZIP(s).
# Usage: ./build.sh [out-dir]
# Produces ocliv-mcp-runtime-linux-<arch>.zip + SHA256SUMS in out-dir
# (default: ./dist). Fails if secrets/state sneak into the allowlist.
set -eu
cd "$(dirname "$0")"
REPO="../.."
OUT="${1:-./dist}"
VERSION="$(cat VERSION)"
EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"

command -v zip >/dev/null || { echo "need zip" >&2; exit 1; }
command -v unzip >/dev/null || { echo "need unzip" >&2; exit 1; }

# Guard: the tree must be clean of runtime state before packaging.
if git -C "$REPO" status --porcelain 2>/dev/null | grep -Eq '\.db$|\.pem$|\.key$|token'; then
  echo "refusing: runtime state or secrets present in tree" >&2
  exit 1
fi

# The packaged `ocliv version` must match VERSION.
if ! go run "./$REPO/cmd/ocliv" version 2>/dev/null | grep -q "$VERSION"; then
  echo "version mismatch: cmd/ocliv does not report $VERSION" >&2
  exit 1
fi

mkdir -p "$OUT"
rm -f "$OUT"/ocliv-mcp-runtime-*.zip "$OUT"/SHA256SUMS

build_arch() {
  arch="$1"
  rm -rf "stage-$arch"
  mkdir -p "stage-$arch/bin" "stage-$arch/config" "stage-$arch/caddy" \
    "stage-$arch/systemd" "stage-$arch/scripts" "stage-$arch/docs"
  GOOS=linux GOARCH="$arch" go build -o "stage-$arch/bin/ocliv" "$REPO/cmd/ocliv"
  GOOS=linux GOARCH="$arch" go build -o "stage-$arch/bin/mcp-auth-fixture" "$REPO/tests/staging/mcp-auth-fixture"
  chmod 0755 "stage-$arch/bin/ocliv" "stage-$arch/bin/mcp-auth-fixture"
  cp config/*.example "stage-$arch/config/"
  cp "$REPO/packaging/caddy/Caddyfile.single-host" "$REPO/packaging/caddy/Caddyfile.funnel" "stage-$arch/caddy/"
  cp "$REPO/packaging/systemd/ocliv-relay.service" "$REPO/packaging/systemd/ocliv-relay-launch.sh" "stage-$arch/systemd/"
  cp systemd/*.service "stage-$arch/systemd/"
  cp scripts/*.sh "stage-$arch/scripts/"
  cp "$REPO/packaging/install/install.sh" "stage-$arch/scripts/install.sh"
  cp "$REPO/packaging/install/backup-restore.sh" "stage-$arch/scripts/backup-restore.sh"
  chmod 0755 "stage-$arch/scripts/"*.sh "stage-$arch/systemd/ocliv-relay-launch.sh"
  cp docs/* "stage-$arch/docs/"
  cp "$REPO/docs/MCP-HOSTING.md" "stage-$arch/docs/"
  cp VERSION "stage-$arch/"
  find "stage-$arch" -exec touch -h -d "@$EPOCH" {} +
  (cd "stage-$arch" && find . | LC_ALL=C sort | zip -X -9 -q -@ "$OLDPWD/$OUT/ocliv-mcp-runtime-linux-$arch.zip")
}

build_arch amd64
build_arch arm64
rm -rf stage-amd64 stage-arm64

(cd "$OUT" && sha256sum ocliv-mcp-runtime-*.zip > SHA256SUMS)
echo "--- contents:"; unzip -l "$OUT/ocliv-mcp-runtime-linux-amd64.zip"
