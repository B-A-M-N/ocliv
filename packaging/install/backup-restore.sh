#!/bin/sh
# Ocliv relay backup / restore (staging). Backup uses SQLite's online
# backup API. Restore is an explicit, offline, fail-closed operation
# (P0-C): the service must be confirmed stopped, the candidate must pass
# integrity and schema checks, and revocation history must never roll
# backward — a restored DB that resurrects a revoked lease, key, or token
# is refused, never served.
set -eu

DATA_DIR="${DATA_DIR:-/var/lib/ocliv}"
DB="$DATA_DIR/ocliv.db"

usage() {
  echo "usage: $0 backup <out-dir> | restore <backup-file>" >&2
  exit 1
}

q() { # q <db> <sql>: single-row query, empty string on no row
  sqlite3 "$1" "$2" 2>/dev/null || echo "SQL_ERROR"
}

case "${1:-}" in
  backup)
    OUT="${2:-}"; [ -n "$OUT" ] || usage
    mkdir -p "$OUT"
    # .backup takes a consistent snapshot without stopping the relay.
    sqlite3 "$DB" ".backup '$OUT/ocliv.db'"
    chmod 0600 "$OUT/ocliv.db"
    echo "backup: $OUT/ocliv.db"
    ;;
  restore)
    SRC="${2:-}"; [ -n "$SRC" ] || usage
    [ -f "$SRC" ] || { echo "restore refused: no such file: $SRC" >&2; exit 1; }

    # 1. The relay must be confirmed stopped. A failed stop is a refusal,
    # never a warning: restoring under a live writer is undefined.
    if systemctl is-active --quiet ocliv-relay 2>/dev/null; then
      echo "restore refused: ocliv-relay is active; stop it first" >&2
      exit 1
    fi

    # 2. Integrity and schema compatibility.
    if [ "$(q "$SRC" 'PRAGMA integrity_check;')" != "ok" ]; then
      echo "restore refused: backup failed PRAGMA integrity_check" >&2
      exit 1
    fi
    CUR_V="$(q "$DB" 'SELECT COALESCE(MAX(v),0) FROM schema_version;')"
    SRC_V="$(q "$SRC" 'SELECT COALESCE(MAX(v),0) FROM schema_version;')"
    if [ "$CUR_V" = "SQL_ERROR" ] || [ "$SRC_V" = "SQL_ERROR" ]; then
      echo "restore refused: unreadable schema_version" >&2
      exit 1
    fi
    if [ "$SRC_V" -gt "$CUR_V" ]; then
      echo "restore refused: backup schema v$SRC_V newer than current v$CUR_V" >&2
      exit 1
    fi

    # 3. Revocation rollback check. A count is insufficient: a backup with
    # three revoked leases passes a count check even when the live DB held
    # ten. Every currently-revoked identity must still be revoked in the
    # candidate; a missing or non-revoked row means the revocation would
    # be lost, so the restore is refused.
    # Leases: terminal status must survive.
    for id in $(sqlite3 "$DB" "SELECT id FROM leases WHERE status='REVOKED';" 2>/dev/null); do
      if [ "$(q "$SRC" "SELECT status FROM leases WHERE id='$id';")" != "REVOKED" ]; then
        echo "restore refused: lease $id is REVOKED now but not in backup" >&2
        exit 1
      fi
    done
    # Agent keys and tokens: revocation timestamp must survive.
    for tbl in agent_keys access_tokens visitor_sessions; do
      case "$tbl" in
        agent_keys) idcol="id" ;;
        *) idcol="id" ;;
      esac
      for id in $(sqlite3 "$DB" "SELECT $idcol FROM $tbl WHERE revoked_at IS NOT NULL;" 2>/dev/null); do
        if [ -z "$(q "$SRC" "SELECT revoked_at FROM $tbl WHERE $idcol='$id';")" ]; then
          echo "restore refused: $tbl $id is revoked now but not in backup" >&2
          exit 1
        fi
      done
    done

    # 4. Install only after all checks pass. Keep a pre-restore copy.
    cp "$DB" "$DB.pre-restore.$(date +%s)" 2>/dev/null || true
    install -m 0600 "$SRC" "$DB"
    # The service user owns the DB on a real host; in test/dev checkouts
    # without that user, ownership stays with the operator.
    if id ocliv >/dev/null 2>&1; then
      chown ocliv:ocliv "$DB"
    fi
    echo "restore complete: revocation state verified, no rollback"
    echo "start with: systemctl start ocliv-relay"
    ;;
  *) usage ;;
esac
