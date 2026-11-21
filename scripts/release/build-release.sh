#!/usr/bin/env bash
set -euo pipefail

# Clean detached-worktree release builder for Ocliv.
# Usage: ./scripts/release/build-release.sh [--skip-tests] [--allow-missing-tools] [COMMIT_SHA]
#
# Builds reproducible linux/amd64 and linux/arm64 binaries from a clean detached
# git worktree at an exact commit SHA, outputting artifacts, SHA256SUMS, SBOM,
# go version -m, ocliv version --json, and release-manifest.json into dist/<sha>/.

SKIP_TESTS=0
ALLOW_MISSING_TOOLS=0
REF="HEAD"

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-tests) SKIP_TESTS=1; shift ;;
    --allow-missing-tools) ALLOW_MISSING_TOOLS=1; shift ;;
    -h|--help)
      echo "Usage: $0 [--skip-tests] [--allow-missing-tools] [COMMIT_SHA]"
      exit 0
      ;;
    *) REF="$1"; shift ;;
  esac
done

ROOT="$(git rev-parse --show-toplevel)"
SHA="$(git -C "$ROOT" rev-parse --verify "${REF}^{commit}")"
COMMIT_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$SHA")"
BUILD_TIME="$(git -C "$ROOT" show -s --format=%cI "$SHA")"
export SOURCE_DATE_EPOCH="$COMMIT_EPOCH"

OUT="$ROOT/dist/$SHA"
mkdir -p "$OUT"

WT="$(mktemp -d "${TMPDIR:-/tmp}/ocliv-release-${SHA:0:12}.XXXXXX")"
cleanup() {
  git -C "$ROOT" worktree remove --force "$WT" >/dev/null 2>&1 || rm -rf "$WT"
}
trap cleanup EXIT

echo "==> Creating clean detached worktree at $SHA"
git -C "$ROOT" worktree add --detach "$WT" "$SHA" >/dev/null

cd "$WT"
ACTUAL_SHA="$(git rev-parse HEAD)"
if [ "$ACTUAL_SHA" != "$SHA" ]; then
  echo "error: worktree HEAD ($ACTUAL_SHA) != requested SHA ($SHA)" >&2
  exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "error: detached worktree is not clean" >&2
  exit 1
fi

echo "==> Running repository hygiene & go mod verify"
./scripts/check-repo-hygiene.sh
go mod verify
go vet ./...

if [ "$SKIP_TESTS" -eq 0 ]; then
  echo "==> Running full test suite and race gates"
  go test ./... -count=1 -timeout=420s
  go test -race ./internal/cli ./internal/protocol ./internal/identity ./internal/config ./internal/agent ./internal/store ./internal/lease ./internal/setup -count=1 -timeout=300s
  go test -race ./internal/relay -count=1 -timeout=420s
fi

GOVULN_STATUS="skipped"
if command -v govulncheck >/dev/null 2>&1; then
  echo "==> Running govulncheck ./..."
  govulncheck ./... >"$OUT/govulncheck.txt" 2>&1
  GOVULN_STATUS="pass"
else
  if [ "$ALLOW_MISSING_TOOLS" -eq 0 ]; then
    echo "error: govulncheck not installed (install with: go install golang.org/x/vuln/cmd/govulncheck@latest)" >&2
    exit 1
  fi
  echo "warning: govulncheck not installed; recording status=not_installed" >&2
  GOVULN_STATUS="not_installed"
fi

LDFLAGS="-s -w -X ocliv/internal/cli.BuildCommit=${SHA} -X ocliv/internal/cli.BuildTime=${BUILD_TIME} -X ocliv/internal/cli.BuildDirty=false"
BUILD_CMD="CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags=\"${LDFLAGS}\" ./cmd/ocliv"

echo "==> Building linux/amd64 and linux/arm64 artifacts"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="$LDFLAGS" -o "$OUT/ocliv-linux-amd64" ./cmd/ocliv
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="$LDFLAGS" -o "$OUT/ocliv-linux-arm64" ./cmd/ocliv

go version -m "$OUT/ocliv-linux-amd64" >"$OUT/go-version-m-amd64.txt"
go version -m "$OUT/ocliv-linux-arm64" >"$OUT/go-version-m-arm64.txt"

HOST_ARCH="$(go env GOARCH)"
if [ -x "$OUT/ocliv-linux-${HOST_ARCH}" ]; then
  "$OUT/ocliv-linux-${HOST_ARCH}" version --json >"$OUT/ocliv-version.json"
fi

SBOM_FILE=""
SBOM_TOOL="none"
if command -v cyclonedx-gomod >/dev/null 2>&1; then
  echo "==> Generating CycloneDX SBOM via cyclonedx-gomod"
  SBOM_FILE="sbom.cdx.json"
  SBOM_TOOL="cyclonedx-gomod"
  cyclonedx-gomod app -json -output "$OUT/$SBOM_FILE" -main ./cmd/ocliv .
elif command -v syft >/dev/null 2>&1; then
  echo "==> Generating CycloneDX SBOM via syft"
  SBOM_FILE="sbom.cdx.json"
  SBOM_TOOL="syft"
  syft dir:. -o cyclonedx-json="$OUT/$SBOM_FILE"
else
  if [ "$ALLOW_MISSING_TOOLS" -eq 0 ]; then
    echo "error: neither cyclonedx-gomod nor syft is installed for SBOM generation" >&2
    exit 1
  fi
  echo "warning: SBOM tool not installed; generating fallback go-module-inventory.json" >&2
  SBOM_FILE="go-module-inventory.json"
  SBOM_TOOL="go-list-fallback"
  go list -m -json all >"$OUT/$SBOM_FILE"
fi

(
  cd "$OUT"
  sha256sum ocliv-linux-amd64 ocliv-linux-arm64 "$SBOM_FILE" > SHA256SUMS
)

GO_VER="$(go version | awk '{print $3}')"
AMD64_SHA="$(sha256sum "$OUT/ocliv-linux-amd64" | awk '{print $1}')"
ARM64_SHA="$(sha256sum "$OUT/ocliv-linux-arm64" | awk '{print $1}')"
SBOM_SHA="$(sha256sum "$OUT/$SBOM_FILE" | awk '{print $1}')"

python3 - "$OUT/release-manifest.json" "$SHA" "$BUILD_TIME" "$SOURCE_DATE_EPOCH" "$GO_VER" "$AMD64_SHA" "$ARM64_SHA" "$SBOM_FILE" "$SBOM_SHA" "$SBOM_TOOL" "$GOVULN_STATUS" "$BUILD_CMD" "$OUT/ocliv-version.json" <<'PY'
import json, pathlib, sys
(manifest_path, sha, build_time, epoch, go_ver, amd64_sha, arm64_sha,
 sbom_file, sbom_sha, sbom_tool, govuln, build_cmd, ver_json_path) = sys.argv[1:]
ver_info = {}
p = pathlib.Path(ver_json_path)
if p.exists():
    ver_info = json.loads(p.read_text())
manifest = {
    "commit": sha,
    "dirty": False,
    "build_time": build_time,
    "source_date_epoch": int(epoch),
    "go_version": go_ver,
    "protocol_version": ver_info.get("protocol_version", ""),
    "supported_protocols": ver_info.get("supported_protocols", ""),
    "schema_version": ver_info.get("schema_version", 0),
    "govulncheck": govuln,
    "sbom_tool": sbom_tool,
    "artifacts": {
        "ocliv-linux-amd64": {"sha256": amd64_sha},
        "ocliv-linux-arm64": {"sha256": arm64_sha},
    },
    "sbom": {"sha256": sbom_sha, "name": sbom_file},
    "build_command": build_cmd,
}
pathlib.Path(manifest_path).write_text(json.dumps(manifest, indent=2) + "\n")
PY

SIGNING_KEY_FILE="${OCLIV_RELEASE_SIGNING_KEY_FILE:-}"
if [ -z "$SIGNING_KEY_FILE" ] && [ "${OCLIV_UNSIGNED_DEV:-}" != "true" ]; then
  echo "error: OCLIV_RELEASE_SIGNING_KEY_FILE is not set" >&2
  echo "       Set it to an Ed25519 signing key (openssl genpkey -algorithm ed25519 -out key.pem)" >&2
  echo "       To skip signing for local development builds: OCLIV_UNSIGNED_DEV=true" >&2
  exit 1
fi

if [ -n "$SIGNING_KEY_FILE" ]; then
  if [ ! -f "$SIGNING_KEY_FILE" ]; then
    echo "error: signing key file not found: $SIGNING_KEY_FILE" >&2
    exit 1
  fi
  echo "==> Signing release manifest"
  RAWSIG="$OUT/release-manifest.json.sig.raw"
  openssl dgst -sign "$SIGNING_KEY_FILE" -out "$RAWSIG" "$OUT/release-manifest.json"
  xxd -p -cols 64 "$RAWSIG" | tr -d '\n' > "$OUT/release-manifest.json.sig"
  rm -f "$RAWSIG"
  echo "Manifest signed: $OUT/release-manifest.json.sig"
else
  echo "==> WARNING: Unsigned development build (OCLIV_UNSIGNED_DEV=true)"
fi

echo "==> Release bundle written to $OUT"
cat "$OUT/release-manifest.json"
