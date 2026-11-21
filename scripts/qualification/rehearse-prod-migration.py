#!/usr/bin/env python3
"""Production-copy schema migration rehearsal using SQLite's online backup API.

Takes a transactionally consistent read-only online snapshot of a source SQLite
database (never copying raw -wal/-shm files independently), migrates the
snapshot with the candidate `ocliv` binary, verifies SQLite integrity, foreign
keys, canonical semantic digests of security-critical authority columns,
legacy pairing expiration, and full backup/validate/restore + live relay
readiness against the restored DB.

NEVER mutates the source database or touches any running production relay.

Usage:
  rehearse-prod-migration.py --bin /path/to/ocliv --src-db /path/to/ocliv.db
"""
import argparse, hashlib, json, os, shutil, socket, sqlite3, subprocess, sys, tempfile, time
import urllib.request

parser = argparse.ArgumentParser(description="Ocliv transactionally consistent migration rehearsal")
parser.add_argument("--bin", required=True, help="Path to candidate ocliv binary")
parser.add_argument("--src-db", required=True, help="Path to source ocliv.db (read-only online snapshot)")
args = parser.parse_args()

PASS, FAIL = [], []


def check(name, ok, note=""):
    (PASS if ok else FAIL).append(name)
    print(("[PASS]" if ok else "[FAIL]"), name, note, flush=True)


def semantic_digest(conn, sql):
    """Return canonical sorted SHA-256 hex digest of security-critical rows."""
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.OperationalError:
        return "TABLE_ABSENT"
    canon = "\n".join(json.dumps(list(r), separators=(",", ":")) for r in rows)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16] + f"(n={len(rows)})"


def collect_inventory(db_path):
    c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    inv = {
        "schema": c.execute("SELECT MAX(v) FROM schema_version").fetchone()[0],
        "tenants": semantic_digest(c, "SELECT id, status, quotas_json FROM tenants ORDER BY id"),
        "agent_keys": semantic_digest(c, "SELECT id, tenant_id, hex(ed25519_public), status, COALESCE(revoked_at,'') FROM agent_keys ORDER BY id"),
        "leases": semantic_digest(c, "SELECT id, tenant_id, agent_key_id, hostname, label, port, access_mode, status, COALESCE(expires_at,'') FROM leases ORDER BY id"),
        "terminal_leases": semantic_digest(c, "SELECT id, status, generation, token_generation FROM leases WHERE status IN ('CLOSED','EXPIRED','REVOKED') ORDER BY id"),
        "mcp_publications": semantic_digest(c, "SELECT route_id, tenant_id, owner_key_id, external_host, profile, pub_name, COALESCE(revoked_at,'') FROM mcp_publications ORDER BY route_id"),
        "authz_clients": semantic_digest(c, "SELECT id, COALESCE(tenant_id,''), COALESCE(route_id,''), COALESCE(revoked_at,'') FROM authz_clients ORDER BY id"),
        "authz_grants": semantic_digest(c, "SELECT client_id, tenant_id, route_id, status FROM authz_grants ORDER BY client_id, tenant_id, route_id"),
        "authz_revocations": semantic_digest(c, "SELECT jti, client_id, tenant_id, route_id FROM authz_revocations ORDER BY jti"),
    }
    c.close()
    return inv


def pick_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


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

    # Transactionally consistent read-only online snapshot via SQLite backup API.
    src_conn = sqlite3.connect(f"file:{args.src_db}?mode=ro", uri=True)
    src_journal_mode = src_conn.execute("PRAGMA journal_mode").fetchone()[0]
    src_schema = src_conn.execute("SELECT MAX(v) FROM schema_version").fetchone()[0]
    dst_conn = sqlite3.connect(dst_db)
    src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()
    os.chmod(dst_db, 0o600)

    snap_sha = hashlib.sha256(open(dst_db, "rb").read()).hexdigest()
    print(f"SNAPSHOT: src_journal_mode={src_journal_mode} src_schema=V{src_schema} sha256={snap_sha}", flush=True)

    before = collect_inventory(dst_db)
    print("PRE-MIGRATION:", json.dumps(before), flush=True)

    mig = subprocess.run([args.bin, "relay", "pending", "--data", copy_dir], capture_output=True, text=True)
    check("M1: candidate binary opens and migrates online snapshot cleanly", mig.returncode == 0, f"rc={mig.returncode} {mig.stderr[:120]}")

    after = collect_inventory(dst_db)
    print("POST-MIGRATION:", json.dumps(after), flush=True)
    check(f"M2: schema reached V{expected_schema}", after["schema"] == expected_schema, f"got={after['schema']}")
    check("M3: semantic digests of tenants/keys/leases/publications identical",
          after["tenants"] == before["tenants"]
          and after["agent_keys"] == before["agent_keys"]
          and after["leases"] == before["leases"]
          and after["mcp_publications"] == before["mcp_publications"],
          f"tenants={after['tenants']} keys={after['agent_keys']}")
    check("M4: terminal lease tombstones preserved identically",
          after["terminal_leases"] == before["terminal_leases"],
          f"tombstones={after['terminal_leases']}")
    check("M5: OAuth clients, grants & revocations preserved identically",
          after["authz_clients"] == before["authz_clients"]
          and after["authz_grants"] == before["authz_grants"]
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

    # Backup + validate-backup + restore --reset-authority + restored DB validation + live relay readiness.
    bak = os.path.join(work, "migrated.db")
    r_bak = subprocess.run([args.bin, "relay", "backup", "--data", copy_dir, "--out", bak], capture_output=True, text=True)
    r_val = subprocess.run([args.bin, "relay", "validate-backup", "--in", bak], capture_output=True, text=True)
    rst_dir = os.path.join(work, "restored")
    os.makedirs(rst_dir, mode=0o700)
    r_rst = subprocess.run([args.bin, "relay", "restore", "--data", rst_dir, "--in", bak, "--reset-authority", "--relay-stopped"], capture_output=True, text=True)
    rst_db = os.path.join(rst_dir, "ocliv.db")
    rc_ok = r_bak.returncode == 0 and r_val.returncode == 0 and r_rst.returncode == 0 and os.path.exists(rst_db)
    check("M10a: backup + validate-backup + restore --reset-authority exit 0", rc_ok, f"bak={r_bak.returncode} val={r_val.returncode} rst={r_rst.returncode}")

    if rc_ok:
        rc_conn = sqlite3.connect(rst_db)
        r_ic = rc_conn.execute("PRAGMA integrity_check").fetchone()[0]
        r_fk = rc_conn.execute("PRAGMA foreign_key_check").fetchall()
        r_sv = rc_conn.execute("SELECT MAX(v) FROM schema_version").fetchone()[0]
        r_ag = rc_conn.execute("SELECT COUNT(*) FROM authz_grants WHERE status='active'").fetchone()[0]
        r_ik = rc_conn.execute("SELECT COUNT(*) FROM authz_issuer_key").fetchone()[0]
        rc_conn.close()
        rst_inv = collect_inventory(rst_db)
        check("M10b: restored DB integrity/FK/schema/reset-authority semantics valid",
              r_ic == "ok" and len(r_fk) == 0 and r_sv == expected_schema and r_ag == 0 and r_ik == 0
              and rst_inv["tenants"] == after["tenants"]
              and rst_inv["agent_keys"] == after["agent_keys"]
              and rst_inv["mcp_publications"] == after["mcp_publications"],
              f"ic={r_ic} sv={r_sv} active_grants={r_ag} issuer_keys={r_ik}")

        # Boot candidate relay against restored DB on loopback and prove /health/ready == 200.
        lport = pick_free_port()
        hport = pick_free_port()
        rlog = open(os.path.join(work, "restored-relay.log"), "w", encoding="utf-8")
        rproc = subprocess.Popen(
            [args.bin, "relay", "serve", f"--listen=127.0.0.1:{lport}", "--domain=rehearsal.local",
             "--relay-host=127.0.0.1", "--data=" + rst_dir, f"--health-listen=127.0.0.1:{hport}"],
            stdout=rlog, stderr=subprocess.STDOUT,
        )
        ready_ok = False
        try:
            for _ in range(50):
                try:
                    if urllib.request.urlopen(f"http://127.0.0.1:{hport}/health/ready", timeout=1).status == 200:
                        ready_ok = True
                        break
                except Exception:
                    if rproc.poll() is not None:
                        break
                    time.sleep(0.1)
        finally:
            rproc.terminate()
            try:
                rproc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                rproc.kill()
            rlog.close()
        check("M10c: candidate relay boots and reports /health/ready 200 on restored DB", ready_ok)
finally:
    shutil.rmtree(work, ignore_errors=True)

print(f"\n== MIGRATION REHEARSAL SUMMARY ==\nPASS {len(PASS)}\nFAIL {len(FAIL)} {FAIL}")
if FAIL:
    sys.exit(1)
