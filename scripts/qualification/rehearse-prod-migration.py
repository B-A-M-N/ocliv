#!/usr/bin/env python3
"""Production-copy schema migration rehearsal (read-only against source DB).

Copies a source SQLite database (plus any -wal/-shm sidecars) into an isolated
scratch directory, migrates the copy with the candidate `ocliv` binary, verifies
SQLite integrity, foreign keys, preserved keys/tenants/leases/publications/grants/
revocations/tombstones, legacy pairing expiration, and backup/restore guards.

NEVER mutates the source database or touches any running production relay.

Usage:
  rehearse-prod-migration.py --bin /path/to/ocliv --src-db /path/to/ocliv.db
"""
import argparse, json, os, shutil, sqlite3, subprocess, sys, tempfile

parser = argparse.ArgumentParser(description="Ocliv production-copy migration rehearsal")
parser.add_argument("--bin", required=True, help="Path to candidate ocliv binary")
parser.add_argument("--src-db", required=True, help="Path to source ocliv.db (read-only; copied before use)")
args = parser.parse_args()

PASS, FAIL = [], []


def check(name, ok, note=""):
    (PASS if ok else FAIL).append(name)
    print(("[PASS]" if ok else "[FAIL]"), name, note, flush=True)


def query_counts(db_path):
    c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    out = {}
    out["schema"] = c.execute("SELECT MAX(v) FROM schema_version").fetchone()[0]
    for tbl in ("tenants", "agent_keys", "leases", "mcp_publications", "authz_clients", "authz_grants", "authz_revocations"):
        try:
            out[tbl] = c.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        except sqlite3.OperationalError:
            out[tbl] = 0
    try:
        out["revoked_keys"] = c.execute("SELECT COUNT(*) FROM agent_keys WHERE status='revoked'").fetchone()[0]
        out["terminal_leases"] = c.execute("SELECT COUNT(*) FROM leases WHERE status IN ('CLOSED','EXPIRED','REVOKED')").fetchone()[0]
    except sqlite3.OperationalError:
        out["revoked_keys"] = 0
        out["terminal_leases"] = 0
    c.close()
    return out


ver_res = subprocess.run([args.bin, "version", "--json"], capture_output=True, text=True)
if ver_res.returncode != 0:
    print("FAIL: candidate binary failed version --json:", ver_res.stderr, file=sys.stderr)
    sys.exit(1)
expected_schema = int(json.loads(ver_res.stdout)["schema_version"])

work = tempfile.mkdtemp(prefix="ocliv-mig-rehearsal-")
os.chmod(work, 0o700)
try:
    copy_dir = os.path.join(work, "data")
    os.makedirs(copy_dir, mode=0o700)
    dst_db = os.path.join(copy_dir, "ocliv.db")
    shutil.copy2(args.src_db, dst_db)
    os.chmod(dst_db, 0o600)
    for suf in ("-wal", "-shm"):
        if os.path.exists(args.src_db + suf):
            shutil.copy2(args.src_db + suf, dst_db + suf)
            os.chmod(dst_db + suf, 0o600)

    before = query_counts(dst_db)
    print("PRE-MIGRATION:", json.dumps(before), flush=True)

    # Trigger migration by running a read-write operator command (`relay tenants list` or `relay pending`).
    mig = subprocess.run([args.bin, "relay", "pending", "--data", copy_dir], capture_output=True, text=True)
    check("M1: candidate binary opens and migrates copy cleanly", mig.returncode == 0, f"rc={mig.returncode} {mig.stderr[:120]}")

    after = query_counts(dst_db)
    print("POST-MIGRATION:", json.dumps(after), flush=True)
    check(f"M2: schema reached V{expected_schema}", after["schema"] == expected_schema, f"got={after['schema']}")
    check("M3: tenants/keys/leases/publications preserved",
          after["tenants"] == before["tenants"]
          and after["agent_keys"] == before["agent_keys"]
          and after["leases"] == before["leases"]
          and after["mcp_publications"] == before["mcp_publications"],
          f"before={before} after={after}")
    check("M4: revoked keys & terminal lease tombstones preserved",
          after["revoked_keys"] == before["revoked_keys"]
          and after["terminal_leases"] == before["terminal_leases"],
          f"revoked_keys={after['revoked_keys']} terminal_leases={after['terminal_leases']}")
    check("M5: OAuth grants & revocations preserved",
          after["authz_grants"] == before["authz_grants"]
          and after["authz_revocations"] == before["authz_revocations"],
          f"grants={after['authz_grants']} revocations={after['authz_revocations']}")

    c = sqlite3.connect(dst_db)
    ic = c.execute("PRAGMA integrity_check").fetchone()[0]
    fk = c.execute("PRAGMA foreign_key_check").fetchall()
    legacy_unpolled = c.execute("SELECT COUNT(*) FROM pairing_requests WHERE status='pending' AND poll_verifier IS NULL").fetchone()[0]
    dup_pending = c.execute("SELECT COUNT(*) FROM (SELECT key_id FROM pairing_requests WHERE status='pending' GROUP BY key_id HAVING COUNT(*)>1)").fetchone()[0]
    c.close()
    check("M6: PRAGMA integrity_check ok", ic == "ok", ic)
    check("M7: PRAGMA foreign_key_check empty", len(fk) == 0, str(fk[:3]))
    check("M8: zero unpollable legacy pending pairing rows", legacy_unpolled == 0, f"count={legacy_unpolled}")
    check("M9: at most one pending pairing row per key_id", dup_pending == 0, f"dups={dup_pending}")

    # Backup + validate-backup + restore --reset-authority rehearsal on the migrated copy.
    bak = os.path.join(work, "migrated.db")
    r_bak = subprocess.run([args.bin, "relay", "backup", "--data", copy_dir, "--out", bak], capture_output=True, text=True)
    r_val = subprocess.run([args.bin, "relay", "validate-backup", "--in", bak], capture_output=True, text=True)
    rst_dir = os.path.join(work, "restored")
    os.makedirs(rst_dir, mode=0o700)
    r_rst = subprocess.run([args.bin, "relay", "restore", "--data", rst_dir, "--in", bak, "--reset-authority", "--relay-stopped"], capture_output=True, text=True)
    check("M10: backup + validate-backup + restore rehearsal on migrated copy",
          r_bak.returncode == 0 and r_val.returncode == 0 and r_rst.returncode == 0,
          f"bak={r_bak.returncode} val={r_val.returncode} rst={r_rst.returncode}")
finally:
    shutil.rmtree(work, ignore_errors=True)

print(f"\n== MIGRATION REHEARSAL SUMMARY ==\nPASS {len(PASS)}\nFAIL {len(FAIL)} {FAIL}")
if FAIL:
    sys.exit(1)
