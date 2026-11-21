#!/bin/sh
# install-client.sh — publisher bootstrap installer for Ocliv
# Usage: sh install-client.sh RELAY_URL
#
# RELAY_URL may also be supplied via the OCLIV_RELAY_URL environment variable.
#
# Requirements: curl or wget, sha256sum, openssl (3.x for Ed25519), uname —
# no Go, Git, Caddy, Docker, or source tree required. Installs to
# /usr/local/bin (root) or ~/.local/bin (non-root).

set -eu

RELAY_URL="${1:-${OCLIV_RELAY_URL:-}}"

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf 'info: %s\n' "$*"; }

# Canonical trusted Ed25519 key set synced from internal/installer/release-trust.json.
# Format: one "<key_id>|<status>|<64-hex-ed25519-pub>" entry per line.
# Statuses: active, retiring (accepted during rotation), revoked (always rejected).
# OCLIV_SIGNING_PUBLIC_KEY_PEM may override for isolated test harnesses.
TRUSTED_RELEASE_KEYS='release-2026-v1-placeholder|active|0000000000000000000000000000000000000000000000000000000000000000'
SIGNING_PUBLIC_KEY_PEM="${OCLIV_SIGNING_PUBLIC_KEY_PEM:-}"

# Validate RELAY_URL: require HTTPS for non-loopback hosts; HTTP permitted only
# for explicit loopback development (127.*, localhost, [::1]).
[ -n "$RELAY_URL" ] || die "usage: $0 RELAY_URL  (or set OCLIV_RELAY_URL)"
RELAY_URL="${RELAY_URL%/}"
case "$RELAY_URL" in
    https://*) ;;
    http://127.*|http://localhost|http://localhost:*|http://\[::1\]|http://\[::1\]:*) ;;
    *) die "RELAY_URL must use https:// (http:// is only permitted for loopback development): $RELAY_URL" ;;
esac
case "$RELAY_URL" in
    *@*|*\#*) die "RELAY_URL must not contain userinfo or fragments" ;;
esac

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
    INSTALL_DIR="${OCLIV_INSTALL_DIR:-/usr/local/bin}"
else
    INSTALL_DIR="${OCLIV_INSTALL_DIR:-${HOME}/.local/bin}"
fi
mkdir -p "$INSTALL_DIR"
DEST="${INSTALL_DIR}/ocliv"
info "install destination: $DEST"

MANIFEST_URL="${RELAY_URL}/.well-known/ocliv-release-manifest.json"
ARTIFACT_URL="${RELAY_URL}/.well-known/ocliv-artifacts/${ARTIFACT}"

# ---------------------------------------------------------------------------
# Portable downloader: prefers curl, falls back to wget. Refuses redirects.
# ---------------------------------------------------------------------------
_fetch_to_file() {
    # $1 = URL, $2 = destination path
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --retry 3 --retry-delay 2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget --max-redirect=0 -qO "$2" "$1"
    else
        die "neither curl nor wget found; install one and retry"
    fi
}

# ---------------------------------------------------------------------------
# Verify OpenSSL 3 Ed25519 (pkeyutl -rawin) capability early before download.
# ---------------------------------------------------------------------------
command -v openssl >/dev/null 2>&1 || die "openssl 3+ not found; it is required for Ed25519 manifest signature verification"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
OPENSSL_VER="$(openssl version 2>/dev/null || true)"
case "$OPENSSL_VER" in
    OpenSSL\ 3.*|OpenSSL\ 4.*|LibreSSL\ 3.*|LibreSSL\ 4.*) ;;
    *)
        if ! openssl pkeyutl -help 2>&1 | grep -q -- '-rawin'; then
            die "installed openssl ($OPENSSL_VER) does not support Ed25519 'pkeyutl -rawin'; upgrade to OpenSSL 3+"
        fi
        ;;
esac

# Convert a 64-hex raw Ed25519 public key into SubjectPublicKeyInfo PEM
# using ASN.1 prefix 302a300506032b6570032100 + 32-byte key.
_hex_to_ed25519_pem() {
    _hex="$1"
    _spki="302a300506032b6570032100${_hex}"
    printf '%s\n' '-----BEGIN PUBLIC KEY-----'
    if command -v xxd >/dev/null 2>&1; then
        printf '%s' "$_spki" | xxd -r -p | openssl base64 -A
        printf '\n'
    else
        # Pure POSIX octal conversion for minimal environments without xxd/python.
        _oct="$(printf '%s' "$_spki" | sed 's/../\\x&/g')"
        printf "$_oct" | openssl base64 -A
        printf '\n'
    fi
    printf '%s\n' '-----END PUBLIC KEY-----'
}

SIGFILE="$(mktemp)"
RAWSIGFILE=""
PUBKEYFILE="$(mktemp)"
MANIFEST_TMPFILE="$(mktemp)"
TMPFILE=""
PREV_TMP=""
cleanup() {
    rm -f "$SIGFILE" "$PUBKEYFILE" "$MANIFEST_TMPFILE"
    [ -n "$RAWSIGFILE" ] && rm -f "$RAWSIGFILE"
    [ -n "$TMPFILE" ] && rm -f "$TMPFILE"
    [ -n "$PREV_TMP" ] && rm -f "$PREV_TMP"
}
trap cleanup EXIT

info "fetching release manifest from $MANIFEST_URL"
_fetch_to_file "$MANIFEST_URL" "$MANIFEST_TMPFILE" || die "failed to fetch manifest from $MANIFEST_URL"

SIG_URL="${MANIFEST_URL}.sig"
info "fetching manifest signature from $SIG_URL"
_fetch_to_file "$SIG_URL" "$SIGFILE" || die "failed to fetch manifest signature (relay must publish $SIG_URL)"

# Accept hex-encoded signature (128 hex chars, optional trailing newline) or raw binary (64 bytes).
SIGLEN="$(wc -c < "$SIGFILE" | tr -d ' \n')"
if [ "$SIGLEN" = "128" ] || [ "$SIGLEN" = "129" ]; then
    RAWSIGFILE="$(mktemp)"
    if command -v xxd >/dev/null 2>&1; then
        xxd -r -p "$SIGFILE" > "$RAWSIGFILE" || die "hex-decode of signature file failed"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys; open(sys.argv[2],"wb").write(bytes.fromhex(open(sys.argv[1]).read().strip()))' "$SIGFILE" "$RAWSIGFILE" \
            || die "hex-decode of signature file failed"
    else
        _shex="$(tr -d ' \r\n' < "$SIGFILE")"
        _soct="$(printf '%s' "$_shex" | sed 's/../\\x&/g')"
        printf "$_soct" > "$RAWSIGFILE" || die "hex-decode of signature file failed"
    fi
    mv "$RAWSIGFILE" "$SIGFILE"
    RAWSIGFILE=""
elif [ "$SIGLEN" != "64" ]; then
    die "manifest signature has unexpected length $SIGLEN (expected 64 raw bytes or 128 hex chars)"
fi

MANIFEST="$(cat "$MANIFEST_TMPFILE")"

# Portable shell JSON value extraction (single-line values only).
_json_str() {
    # $1 = field name
    printf '%s\n' "$MANIFEST" | tr ',' '\n' | grep "\"$1\"" \
        | sed 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
        | head -1
}
_json_bool() {
    printf '%s\n' "$MANIFEST" | tr ',' '\n' | grep "\"$1\"" \
        | sed 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*\([a-z]*\).*/\1/' \
        | head -1
}

DECLARED_KEY_ID="$(_json_str signing_key_id || true)"
AUTHENTICATED_KEY_ID=""
if [ -n "$SIGNING_PUBLIC_KEY_PEM" ]; then
    printf '%s\n' "$SIGNING_PUBLIC_KEY_PEM" > "$PUBKEYFILE"
    if openssl pkeyutl -verify -pubin -inkey "$PUBKEYFILE" -rawin -in "$MANIFEST_TMPFILE" -sigfile "$SIGFILE" >/dev/null 2>&1; then
        AUTHENTICATED_KEY_ID="${DECLARED_KEY_ID:-override-pem}"
    fi
else
    _old_ifs="$IFS"
    IFS='
'
    for _entry in $TRUSTED_RELEASE_KEYS; do
        [ -n "$_entry" ] || continue
        _kid="$(printf '%s' "$_entry" | cut -d'|' -f1)"
        _kst="$(printf '%s' "$_entry" | cut -d'|' -f2)"
        _khex="$(printf '%s' "$_entry" | cut -d'|' -f3)"
        if [ -n "$DECLARED_KEY_ID" ] && [ "$_kid" != "$DECLARED_KEY_ID" ]; then
            continue
        fi
        if [ "$_kst" = "revoked" ]; then
            [ -n "$DECLARED_KEY_ID" ] && die "manifest signing key '$_kid' has been revoked"
            continue
        fi
        if [ "$_kst" != "active" ] && [ "$_kst" != "retiring" ]; then
            continue
        fi
        _hex_to_ed25519_pem "$_khex" > "$PUBKEYFILE"
        if openssl pkeyutl -verify -pubin -inkey "$PUBKEYFILE" -rawin -in "$MANIFEST_TMPFILE" -sigfile "$SIGFILE" >/dev/null 2>&1; then
            AUTHENTICATED_KEY_ID="$_kid"
            break
        fi
    done
    IFS="$_old_ifs"
fi
[ -n "$AUTHENTICATED_KEY_ID" ] || die "manifest signature verification FAILED — refusing to install (manifest may have been tampered with)"
info "manifest signature verified (signing_key_id=$AUTHENTICATED_KEY_ID)"

NON_PROD="$(_json_bool non_production || true)"
if [ "$NON_PROD" = "true" ]; then
    die "refusing installation: manifest is marked non_production=true"
fi

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

EXPECTED_COMMIT="$(_json_str commit)"
[ -n "$EXPECTED_COMMIT" ] || die "refusing installation: manifest 'commit' field missing"

# Extract SHA256 for the target artifact from the artifacts block.
EXPECTED_SHA256="$(printf '%s\n' "$MANIFEST" \
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
info "expected SHA256: $EXPECTED_SHA256 (commit: $EXPECTED_COMMIT)"

# ---------------------------------------------------------------------------
# Download and verify the artifact inside INSTALL_DIR (same filesystem).
# ---------------------------------------------------------------------------
TMPFILE="$(mktemp "${INSTALL_DIR}/.ocliv-install.XXXXXX")"

info "downloading $ARTIFACT from $ARTIFACT_URL"
_fetch_to_file "$ARTIFACT_URL" "$TMPFILE" || die "failed to download artifact"

info "verifying SHA256..."
ACTUAL_SHA256="$(sha256sum "$TMPFILE" | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    die "SHA256 mismatch: expected $EXPECTED_SHA256, got $ACTUAL_SHA256"
fi
info "SHA256 verified"

chmod 755 "$TMPFILE"

# Pre-swap candidate validation: verify the staged binary runs and reports the
# exact commit from the authenticated manifest BEFORE replacing any live binary.
_verify_binary() {
    _bin="$1"
    _vjson="$("$_bin" version --json 2>/dev/null)" || return 1
    _bcommit="$(printf '%s\n' "$_vjson" | tr ',' '\n' | grep '"build_commit"' \
        | sed 's/.*"build_commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | head -1)"
    if [ -z "$_bcommit" ]; then
        _bcommit="$(printf '%s\n' "$_vjson" | tr ',' '\n' | grep '"commit"' \
            | sed 's/.*"commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | head -1)"
    fi
    [ -n "$_bcommit" ] && [ "$_bcommit" = "$EXPECTED_COMMIT" ]
}

if ! _verify_binary "$TMPFILE"; then
    die "staged binary failed pre-swap verification (version --json failed or commit != $EXPECTED_COMMIT)"
fi
info "staged binary pre-swap verification passed (commit $EXPECTED_COMMIT)"

# ---------------------------------------------------------------------------
# Install atomically with safe .prev preservation and post-swap rollback.
# ---------------------------------------------------------------------------
HAD_PREV=0
if [ -L "$DEST" ]; then
    die "refusing to replace symlink destination $DEST"
fi
if [ -f "$DEST" ]; then
    PREV_TMP="$(mktemp "${INSTALL_DIR}/.ocliv-prev.XXXXXX")"
    cp -p "$DEST" "$PREV_TMP" || die "failed to preserve previous binary"
    mv "$PREV_TMP" "${DEST}.prev" || die "failed to place previous binary backup"
    PREV_TMP=""
    HAD_PREV=1
fi

mv "$TMPFILE" "$DEST"
TMPFILE=""

# Best-effort directory fsync for crash durability.
if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY); os.fsync(fd); os.close(fd)' "$INSTALL_DIR" 2>/dev/null || true
fi

# Post-swap verification: must succeed and match EXPECTED_COMMIT, or rollback.
if ! _verify_binary "$DEST"; then
    printf 'error: post-install verification failed: installed binary did not execute or commit mismatch\n' >&2
    if [ "$HAD_PREV" = "1" ] && [ -f "${DEST}.prev" ]; then
        mv "${DEST}.prev" "$DEST"
        printf 'rolled back to previous version\n' >&2
    else
        rm -f "$DEST"
    fi
    exit 1
fi

VERSION="$("$DEST" version --json 2>/dev/null \
    | tr ',' '\n' \
    | grep '"version"' \
    | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
    | head -1)"
[ -n "$VERSION" ] || die "post-install version check returned empty version"
info "installed: $DEST (version $VERSION, commit $EXPECTED_COMMIT)"

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
