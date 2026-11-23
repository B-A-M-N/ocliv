#!/bin/sh
# install-relay.sh — signed GitHub Release bootstrap installer for Ocliv (Linux)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/B-A-M-N/ocliv/master/packaging/install/install-relay.sh | sudo sh
#   sh install-relay.sh [--version v0.1.0] [--dir /usr/local/bin]
#
# Downloads release-manifest.json, release-manifest.json.sig, and the platform
# binary from GitHub Releases, verifies the Ed25519 signature against the
# embedded release trust root, verifies SHA-256, and installs atomically.
# Requirements: curl or wget, sha256sum, openssl 3+, uname (no Go/Git/Docker).

set -eu

REPO="${OCLIV_GITHUB_REPO:-B-A-M-N/ocliv}"
VERSION="${OCLIV_VERSION:-latest}"
INSTALL_DIR="${OCLIV_INSTALL_DIR:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift ;;
        --dir) INSTALL_DIR="$2"; shift 2 ;;
        --dir=*) INSTALL_DIR="${1#*=}"; shift ;;
        -h|--help)
            echo "usage: $0 [--version latest|vX.Y.Z] [--dir PATH]"
            exit 0 ;;
        *) echo "error: unknown argument $1" >&2; exit 1 ;;
    esac
done

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf 'info: %s\n' "$*"; }

# BEGIN GENERATED TRUST ROOT (from internal/installer/release-trust.json)
TRUSTED_RELEASE_KEYS='release-2026-v1|active|219093940b4311b518f3d5c0a2b4f851a7ccbf510bec5d8963f41e5dbb3a714b'
# END GENERATED TRUST ROOT

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported architecture: $ARCH (supported: x86_64, aarch64/arm64)" ;;
esac
case "$OS" in
    linux) ;;
    *) die "unsupported OS: $OS (Ocliv v0.1 supports systemd-based Linux only)" ;;
esac

ARTIFACT="ocliv-${OS}-${ARCH}"
if [ -z "$INSTALL_DIR" ]; then
    if [ "$(id -u)" = "0" ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
    fi
fi
mkdir -p "$INSTALL_DIR"
DEST="${INSTALL_DIR}/ocliv"

if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

command -v openssl >/dev/null 2>&1 || die "openssl 3+ is required for Ed25519 manifest signature verification"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

_fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "neither curl nor wget found"
    fi
}

_hex_to_bin() {
    awk 'BEGIN {
        for (i = 0; i < 16; i++) hex[substr("0123456789abcdef", i+1, 1)] = i
        for (i = 0; i < 16; i++) hex[substr("0123456789ABCDEF", i+1, 1)] = i
    }
    {
        gsub(/[^0-9a-fA-F]/, "", $0)
        for (i = 1; i <= length($0); i += 2) {
            v = hex[substr($0, i, 1)] * 16 + hex[substr($0, i+1, 1)]
            printf "\\%03o", v
        }
    }
    END { printf "\n" }' | {
        IFS= read -r _oct || [ -n "$_oct" ]
        printf '%b' "$_oct"
    }
}

_hex_to_ed25519_pem() {
    _spki="302a300506032b6570032100${1}"
    printf '%s\n' '-----BEGIN PUBLIC KEY-----'
    printf '%s' "$_spki" | _hex_to_bin | openssl base64 -A
    printf '\n%s\n' '-----END PUBLIC KEY-----'
}

TMPDIR_WORK="$(mktemp -d "${TMPDIR:-/tmp}/ocliv-install.XXXXXX")"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

MANIFEST="${TMPDIR_WORK}/release-manifest.json"
SIG_RAW="${TMPDIR_WORK}/release-manifest.json.sig.raw"
SIG="${TMPDIR_WORK}/release-manifest.json.sig"
BIN="${TMPDIR_WORK}/${ARTIFACT}"

info "fetching signed release manifest (${VERSION}) for ${ARTIFACT}..."
_fetch "${BASE_URL}/release-manifest.json" "$MANIFEST"
_fetch "${BASE_URL}/release-manifest.json.sig" "$SIG_RAW"

SIGLEN="$(wc -c < "$SIG_RAW" | tr -d ' ')"
if [ "$SIGLEN" = "64" ]; then
    cp "$SIG_RAW" "$SIG"
else
    SIGHEX="$(tr -d ' \t\r\n' < "$SIG_RAW")"
    if [ "${#SIGHEX}" = "128" ]; then
        printf '%s' "$SIGHEX" | _hex_to_bin > "$SIG"
    else
        die "manifest signature has unexpected length $SIGLEN (expected 64 raw bytes or 128 hex chars)"
    fi
fi

VERIFIED=0
OLD_IFS="$IFS"
IFS='
'
for entry in $TRUSTED_RELEASE_KEYS; do
    IFS='|' read -r kid status khex <<EOF
$entry
EOF
    [ "$status" = "active" ] || [ "$status" = "retiring" ] || continue
    PEM="${TMPDIR_WORK}/key-${kid}.pem"
    _hex_to_ed25519_pem "$khex" > "$PEM"
    if openssl pkeyutl -verify -pubin -inkey "$PEM" -rawin -in "$MANIFEST" -sigfile "$SIG" >/dev/null 2>&1; then
        info "verified Ed25519 manifest signature (key=${kid})"
        VERIFIED=1
        break
    fi
done
IFS="$OLD_IFS"
[ "$VERIFIED" -eq 1 ] || die "release-manifest.json signature verification failed against trusted keys"

EXPECTED_SHA="$(awk -v art="\"${ARTIFACT}\"" '
    $0 ~ art { found=1 }
    found && /"sha256"/ {
        gsub(/.*"sha256"[[:space:]]*:[[:space:]]*"/, "")
        gsub(/".*/, "")
        print
        exit
    }
' "$MANIFEST")"
[ -n "$EXPECTED_SHA" ] || die "could not extract sha256 for ${ARTIFACT} from release-manifest.json"

info "downloading ${ARTIFACT}..."
_fetch "${BASE_URL}/${ARTIFACT}" "$BIN"

ACTUAL_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || die "SHA-256 mismatch: expected ${EXPECTED_SHA}, got ${ACTUAL_SHA}"
info "verified SHA-256 (${ACTUAL_SHA})"

chmod 0755 "$BIN"
"$BIN" version >/dev/null 2>&1 || die "downloaded binary failed self-check"

TMP_DEST="${INSTALL_DIR}/.ocliv.new.$$"
cp "$BIN" "$TMP_DEST"
chmod 0755 "$TMP_DEST"
mv -f "$TMP_DEST" "$DEST"
info "installed Ocliv to ${DEST}"
"$DEST" version
