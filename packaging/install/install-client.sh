#!/bin/sh
# install-client.sh — publisher bootstrap installer for Ocliv
# Usage: sh install-client.sh RELAY_URL
#
# RELAY_URL may also be supplied via the OCLIV_RELAY_URL environment variable.
#
# Requirements: curl or wget, sha256sum, uname — no Go, Git, Caddy, Docker,
# or source tree required. Installs to /usr/local/bin (root) or
# ~/.local/bin (non-root).

set -e

RELAY_URL="${1:-$OCLIV_RELAY_URL}"

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf 'info: %s\n' "$*"; }

# Ed25519 public key for manifest signature verification (SubjectPublicKeyInfo PEM).
# Replace with real production key before shipping.
# Placeholder value: all-zero key — intentionally invalid, will fail signature checks.
SIGNING_PUBLIC_KEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PUBLIC KEY-----'

# Detect OS and architecture.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported architecture: $ARCH (supported: x86_64, aarch64/arm64)" ;;
esac
case "$OS" in
    linux) ;;
    *) die "unsupported OS: $OS (this installer supports Linux only)" ;;
esac

ARTIFACT="ocliv-${OS}-${ARCH}"
info "target platform: $ARTIFACT"

# Determine installation directory.
if [ "$(id -u)" = "0" ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi
DEST="${INSTALL_DIR}/ocliv"
info "install destination: $DEST"

[ -n "$RELAY_URL" ] || die "usage: $0 RELAY_URL  (or set OCLIV_RELAY_URL)"
RELAY_URL="${RELAY_URL%/}"

MANIFEST_URL="${RELAY_URL}/.well-known/ocliv-release-manifest.json"
ARTIFACT_URL="${RELAY_URL}/.well-known/ocliv-artifacts/${ARTIFACT}"

# ---------------------------------------------------------------------------
# Portable downloader: prefers curl, falls back to wget.
# ---------------------------------------------------------------------------
_fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        die "neither curl nor wget found; install one and retry"
    fi
}

_fetch_to_file() {
    # $1 = URL, $2 = destination path
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "neither curl nor wget found"
    fi
}

# ---------------------------------------------------------------------------
# Fetch and validate the release manifest.
# ---------------------------------------------------------------------------
info "fetching release manifest from $MANIFEST_URL"
MANIFEST="$(_fetch "$MANIFEST_URL")" || die "failed to fetch manifest from $MANIFEST_URL"

# Verify manifest signature before parsing any values.
command -v openssl >/dev/null 2>&1 || die "openssl not found; it is required for signature verification (install openssl 3)"

SIG_URL="${MANIFEST_URL}.sig"
SIGFILE="$(mktemp)"
PUBKEYFILE="$(mktemp)"
MANIFEST_TMPFILE="$(mktemp)"
trap 'rm -f "$SIGFILE" "$PUBKEYFILE" "$MANIFEST_TMPFILE"' EXIT

info "fetching manifest signature from $SIG_URL"
_fetch_to_file "$SIG_URL" "$SIGFILE" || die "failed to fetch manifest signature (relay must publish $SIG_URL)"

# Accept hex-encoded signature (128 hex chars) or raw binary (64 bytes).
SIGLEN="$(wc -c < "$SIGFILE" | tr -d ' \n')"
if [ "$SIGLEN" = "128" ] || [ "$SIGLEN" = "129" ]; then
    RAWSIGFILE="$(mktemp)"
    trap 'rm -f "$SIGFILE" "$PUBKEYFILE" "$MANIFEST_TMPFILE" "$RAWSIGFILE"' EXIT
    xxd -r -p "$SIGFILE" > "$RAWSIGFILE" || die "hex-decode of signature file failed"
    mv "$RAWSIGFILE" "$SIGFILE"
fi

printf '%s\n' "$SIGNING_PUBLIC_KEY_PEM" > "$PUBKEYFILE"
printf '%s' "$MANIFEST" > "$MANIFEST_TMPFILE"
openssl dgst -verify "$PUBKEYFILE" -signature "$SIGFILE" "$MANIFEST_TMPFILE" >/dev/null 2>&1 \
    || die "manifest signature verification FAILED — refusing to install (manifest may have been tampered with)"
info "manifest signature verified"

# Portable shell JSON value extraction (single-line values only).
_json_str() {
    # $1 = field name
    printf '%s' "$MANIFEST" | tr ',' '\n' | grep "\"$1\"" \
        | sed 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
        | head -1
}
_json_bool() {
    printf '%s' "$MANIFEST" | tr ',' '\n' | grep "\"$1\"" \
        | sed 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*\([a-z]*\).*/\1/' \
        | head -1
}

# dirty=false required; fail closed on absent/malformed value.
DIRTY="$(_json_bool dirty)"
case "$DIRTY" in
    false) ;;
    true)  die "refusing installation: manifest reports dirty=true (non-reproducible build)" ;;
    *)     die "refusing installation: manifest 'dirty' field absent or malformed (got '$DIRTY')" ;;
esac

GOVULNCHECK="$(_json_str govulncheck)"
if [ "$GOVULNCHECK" != "pass" ]; then
    die "refusing installation: manifest govulncheck=\"$GOVULNCHECK\" (expected \"pass\")"
fi

# Extract SHA256 for the target artifact from the artifacts block.
# Manifests use: "artifacts": { "ocliv-linux-amd64": { "sha256": "abc..." } }
EXPECTED_SHA256="$(printf '%s' "$MANIFEST" \
    | tr '{}' '\n' \
    | grep -A1 "\"${ARTIFACT}\"" \
    | grep '"sha256"' \
    | sed 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
    | head -1)"
[ -n "$EXPECTED_SHA256" ] || die "artifact \"$ARTIFACT\" not found in manifest"

# Validate SHA256 is exactly 64 lowercase hex characters.
case "$EXPECTED_SHA256" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\
[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\
[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\
[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\
[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\
[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\
[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\
[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) die "manifest SHA256 for $ARTIFACT is not 64 hex characters (got: '$EXPECTED_SHA256')" ;;
esac
info "expected SHA256: $EXPECTED_SHA256"

# ---------------------------------------------------------------------------
# Download and verify the artifact.
# ---------------------------------------------------------------------------
# Create temp file in the destination directory for same-filesystem atomic rename.
TMPFILE="$(mktemp "${INSTALL_DIR}/.ocliv-install.XXXXXX")"
trap 'rm -f "$SIGFILE" "$PUBKEYFILE" "$MANIFEST_TMPFILE" "$TMPFILE"' EXIT

info "downloading $ARTIFACT from $ARTIFACT_URL"
_fetch_to_file "$ARTIFACT_URL" "$TMPFILE" || die "failed to download artifact"

info "verifying SHA256..."
ACTUAL_SHA256="$(sha256sum "$TMPFILE" | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    die "SHA256 mismatch: expected $EXPECTED_SHA256, got $ACTUAL_SHA256"
fi
info "SHA256 verified"

# ---------------------------------------------------------------------------
# Install atomically.
# ---------------------------------------------------------------------------
chmod 755 "$TMPFILE"

# Preserve existing binary for rollback before replacing.
if [ -f "$DEST" ]; then
    cp -p "$DEST" "${DEST}.prev" 2>/dev/null || true
fi

mv "$TMPFILE" "$DEST"
trap 'rm -f "$SIGFILE" "$PUBKEYFILE" "$MANIFEST_TMPFILE"' EXIT
info "installed: $DEST"

# Verify the installed binary executes and reports a valid version.
if ! "$DEST" version --json >/dev/null 2>&1; then
    printf 'error: post-install sanity check failed: installed binary did not execute\n' >&2
    if [ -f "${DEST}.prev" ]; then
        mv "${DEST}.prev" "$DEST"
        printf 'rolled back to previous version\n' >&2
    fi
    exit 1
fi
VERSION="$("$DEST" version --json 2>/dev/null \
    | tr ',' '\n' \
    | grep '"version"' \
    | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
    | head -1)"
info "installed version: ${VERSION:-unknown}"

# ---------------------------------------------------------------------------
# Post-install hints.
# ---------------------------------------------------------------------------
if [ "$(id -u)" != "0" ]; then
    printf '\n'
    printf 'Add %s to your PATH:\n' "$INSTALL_DIR"
    printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
fi

printf '\nOcliv publisher installed successfully.\n'
printf 'Next step: ocliv pair %s\n' "$RELAY_URL"
