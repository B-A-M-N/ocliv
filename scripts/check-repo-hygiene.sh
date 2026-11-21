#!/usr/bin/env bash
set -euo pipefail

# Repository hygiene invariant check (enforced locally and in CI).
# Fails if:
#   1. Unexpected tracked root-level files appear.
#   2. Any tracked file exists under dist/, .scratch/, live/, lab-backup/, or ~/.
#   3. Tracked archives, SQLite DBs, private keys, or oversized binaries (>5 MiB)
#      are committed outside the explicit fixture allowlist.
#   4. New audit-era test filenames (passN / rereview / remediation) are added.

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

FAIL=0

# 1. Tracked root-level entries allowlist.
ALLOWED_ROOT_RE='^(AGENTS\.md|README\.md|go\.mod|go\.sum|\.gitignore|\.github|cmd|docs|integrations|internal|packaging|scripts|skills|tests)$'
while IFS= read -r top; do
  [ -z "$top" ] && continue
  if ! [[ "$top" =~ $ALLOWED_ROOT_RE ]]; then
    echo "HYGIENE FAIL: unexpected tracked root entry: $top" >&2
    FAIL=1
  fi
done < <(git ls-files | awk -F/ '{print $1}' | sort -u)

# 2. Forbidden tracked directories.
while IFS= read -r f; do
  [ -z "$f" ] && continue
  echo "HYGIENE FAIL: forbidden tracked path: $f" >&2
  FAIL=1
done < <(git ls-files | grep -E '^(dist/|\.scratch/|live/|lab-backup/|~/|events\.jsonl$|guidance\.md$)' || true)

# 3. Forbidden generated/secret extensions or oversized files (>5 MiB).
while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    *.zip|*.tar.gz|*.db|*.db-wal|*.db-shm|*.key|*.sqlite)
      echo "HYGIENE FAIL: forbidden tracked archive/db/key artifact: $f" >&2
      FAIL=1
      ;;
  esac
  if [ -f "$f" ]; then
    sz=$(wc -c < "$f")
    if [ "$sz" -gt 5242880 ]; then
      echo "HYGIENE FAIL: tracked file exceeds 5 MiB ($sz bytes): $f" >&2
      FAIL=1
    fi
  fi
done < <(git ls-files)

# 4. Audit-era test filenames.
while IFS= read -r f; do
  [ -z "$f" ] && continue
  echo "HYGIENE FAIL: audit-era test filename not allowed (use behavioral name): $f" >&2
  FAIL=1
done < <(git ls-files | grep -E '_test\.go$' | grep -iE '(pass[0-9]|rereview|remediation)' || true)

if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
if command -v python3 >/dev/null 2>&1 && [ -f scripts/release/render-shell-trust.py ]; then
  python3 scripts/release/render-shell-trust.py --check
fi

echo "OK: repository hygiene checks passed"
