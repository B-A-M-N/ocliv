#!/usr/bin/env bash
set -euo pipefail

# Verified signed-bundle publisher for GitHub Releases.
# Keeps the permanent Ed25519 signing key offline on the operator's trusted
# machine: build & sign with `scripts/release/build-release.sh --production`,
# then verify & publish with this script.
#
# Usage:
#   ./scripts/release/publish-github-release.sh v0.1.0 <EXACT_COMMIT_SHA>

if [ $# -ne 2 ]; then
  echo "usage: $0 <TAG> <COMMIT_SHA>" >&2
  exit 1
fi

TAG="$1"
SHA="$2"

case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "error: tag must match semantic version vX.Y.Z (got $TAG)" >&2
    exit 1 ;;
esac

ROOT="$(git rev-parse --show-toplevel)"
RESOLVED_SHA="$(git -C "$ROOT" rev-parse --verify "${SHA}^{commit}")"
if [ "$RESOLVED_SHA" != "$SHA" ]; then
  echo "error: provide full 40-character commit SHA (resolved $RESOLVED_SHA != $SHA)" >&2
  exit 1
fi

if git -C "$ROOT" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "error: local tag $TAG already exists" >&2
  exit 1
fi
if git -C "$ROOT" ls-remote --tags origin "refs/tags/$TAG" | grep -q .; then
  echo "error: remote tag $TAG already exists on origin" >&2
  exit 1
fi

BUNDLE="$ROOT/dist/$SHA"
if [ ! -d "$BUNDLE" ]; then
  echo "error: release bundle directory not found: $BUNDLE" >&2
  echo "       build it first with: ./scripts/release/build-release.sh --production --release-sequence N $SHA" >&2
  exit 1
fi

for req in ocliv-linux-amd64 ocliv-linux-arm64 SHA256SUMS release-manifest.json release-manifest.json.sig sbom.cdx.json LICENSE; do
  if [ ! -f "$BUNDLE/$req" ]; then
    echo "error: missing required release asset: $BUNDLE/$req" >&2
    exit 1
  fi
done

echo "==> Verifying SHA256SUMS"
(cd "$BUNDLE" && sha256sum -c SHA256SUMS)

echo "==> Verifying release-manifest.json metadata and Ed25519 signature"
python3 - "$ROOT/internal/installer/release-trust.json" "$BUNDLE/release-manifest.json" "$BUNDLE/release-manifest.json.sig" "$SHA" << 'PY'
import base64, json, pathlib, subprocess, sys, tempfile

trust_path, manifest_path, sig_path, want_sha = sys.argv[1:5]
trust = json.loads(pathlib.Path(trust_path).read_text(encoding="utf-8"))
manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))

if manifest.get("commit") != want_sha:
    sys.exit(f"error: manifest commit {manifest.get('commit')!r} != {want_sha!r}")
if manifest.get("dirty") is not False:
    sys.exit("error: manifest dirty != false")
if manifest.get("non_production") is not False:
    sys.exit("error: refusing to publish non_production release bundle")
if manifest.get("govulncheck") != "pass":
    sys.exit(f"error: manifest govulncheck={manifest.get('govulncheck')!r} != 'pass'")
if not isinstance(manifest.get("release_sequence"), int) or manifest["release_sequence"] <= 0:
    sys.exit(f"error: invalid release_sequence={manifest.get('release_sequence')!r}")

kid = manifest.get("signing_key_id", "")
key_hex = None
for k in trust.get("keys", []):
    if k.get("id") == kid and k.get("status") in ("active", "retiring"):
        key_hex = k.get("ed25519")
        break
if not key_hex:
    sys.exit(f"error: signing_key_id {kid!r} not active/retiring in release-trust.json")

spki = bytes.fromhex("302a300506032b6570032100" + key_hex)
pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki).decode("ascii") + "\n-----END PUBLIC KEY-----\n"
raw_sig = pathlib.Path(sig_path).read_bytes()
if len(raw_sig) != 64:
    stripped = raw_sig.strip()
    if len(stripped) == 128:
        try:
            raw_sig = bytes.fromhex(stripped.decode("ascii"))
        except Exception as exc:
            sys.exit(f"error: invalid hex signature in {sig_path}: {exc}")
    else:
        sys.exit(f"error: unexpected signature length {len(raw_sig)} in {sig_path} (want 64 raw bytes or 128 hex chars)")
with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as tf, tempfile.NamedTemporaryFile("wb", suffix=".sig", delete=True) as sf:
    tf.write(pem)
    tf.flush()
    sf.write(raw_sig)
    sf.flush()
    res = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", tf.name, "-rawin", "-in", manifest_path, "-sigfile", sf.name],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        sys.exit(f"error: Ed25519 signature verification failed: {res.stderr.strip()}")
print(f"OK: verified manifest commit={want_sha} sequence={manifest['release_sequence']} key={kid}")
PY

HOST_ARCH="$(go env GOARCH)"
if [ -x "$BUNDLE/ocliv-linux-${HOST_ARCH}" ]; then
  BIN_COMMIT="$("$BUNDLE/ocliv-linux-${HOST_ARCH}" version --json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("build_commit",""))')"
  if [ "$BIN_COMMIT" != "$SHA" ]; then
    echo "error: binary embedded build_commit ($BIN_COMMIT) != $SHA" >&2
    exit 1
  fi
fi

command -v gh >/dev/null 2>&1 || { echo "error: GitHub CLI (gh) is required" >&2; exit 1; }

echo "==> Tagging $TAG at $SHA and pushing tag"
git -C "$ROOT" tag -a "$TAG" "$SHA" -m "Ocliv $TAG"
git -C "$ROOT" push origin "$TAG"

ASSETS=(
  "$BUNDLE/ocliv-linux-amd64#Ocliv for Linux x86_64"
  "$BUNDLE/ocliv-linux-arm64#Ocliv for Linux ARM64"
  "$BUNDLE/SHA256SUMS"
  "$BUNDLE/release-manifest.json"
  "$BUNDLE/release-manifest.json.sig"
  "$BUNDLE/sbom.cdx.json"
  "$BUNDLE/LICENSE"
)
if [ -f "$BUNDLE/THIRD_PARTY_LICENSES" ]; then
  ASSETS+=("$BUNDLE/THIRD_PARTY_LICENSES")
fi

echo "==> Publishing GitHub Release $TAG"
gh release create "$TAG" "${ASSETS[@]}" --title "Ocliv $TAG" --generate-notes
echo "OK: published Ocliv $TAG ($SHA)"
