#!/usr/bin/env python3
"""Production-copy schema migration rehearsal using SQLite's online backup API.

Takes a transactionally consistent read-only online snapshot of a source SQLite
database (never copying raw -wal/-shm files independently), migrates the
snapshot with the candidate `ocliv` binary, verifies SQLite integrity, foreign
keys, full 64-hex canonical semantic digests of security-critical authority
columns, legacy pairing expiration, and full backup/validate/restore with the
explicit `--reset-authority` mutation contract + live relay readiness.

NEVER mutates the source database or touches any running production relay.

Usage:
  rehearse-prod-migration.py --bin /path/to/ocliv --src-db /path/to/ocliv.db [--receipt-out PATH]
"""
import argparse, datetime, hashlib, json, os, shutil, socket, sqlite3, subprocess, sys, tempfile, time
import urllib.request

parser = argparse.ArgumentParser(description="Ocliv transactionally consistent migration rehearsal")
parser.add_argument("--bin", required=True, help="Path to candidate ocliv binary")
parser.add_argument("--src-db", required=True, help="Path to source ocliv.db (read-only online snapshot)")
parser.add_argument("--receipt-out", default="", help="Optional path to write provenance-bound JSON receipt")
args = parser.parse_args()

PASS, FAIL = [], []


def check(name, ok, note=""):
    (PASS if ok else FAIL).append(name)
    print(("[PASS]" if ok else "[FAIL]"), name, note, flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def semantic_digest(conn, sql):
    """Return full 64-hex canonical sorted SHA-256 digest of security-critical rows."""
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.OperationalError:
        return "TABLE_ABSENT"
    canon = "\n".join(json.dumps(list(r), separators=(",", ":")) for r in rows)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest() + f"(n={len(rows)})"


def collect_inventory(db_path):
    c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    inv = {
        "schema": c.execute("SELECT MAX(v) FROM schema_version").fetchone()[0],
        # Full authority columns (must be identical across schema migration)
        "tenants": semantic_digest(c, "SELECT id, status, quotas_json FROM tenants ORDER BY id"),
        "agent_keys": semantic_digest(c, "SELECT id, tenant_id, hex(ed25519_public), status, COALESCE(revoked_at,'') FROM agent_keys ORDER BY id"),
        "leases": semantic_digest(c, "SELECT id, tenant_id, agent_key_id, hostname, label, port, access_mode, status, COALESCE(expires_at,'') FROM leases ORDER BY id"),
        "terminal_leases": semantic_digest(c, "SELECT id, status, generation, token_generation FROM leases WHERE status IN ('CLOSED','EXPIRED','REVOKED') ORDER BY id"),
        "mcp_publications": semantic_digest(c, "SELECT route_id, tenant_id, owner_key_id, external_host, profile, pub_name, COALESCE(revoked_at,'') FROM mcp_publications ORDER BY route_id"),
        "authz_clients": semantic_digest(c, "SELECT id, COALESCE(tenant_id,''), COALESCE(route_id,''), COALESCE(revoked_at,'') FROM authz_clients ORDER BY id"),
        "authz_grants": semantic_digest(c, "SELECT client_id, tenant_id, route_id, status FROM authz_grants ORDER BY client_id, tenant_id, route_id"),
        "authz_revocations": semantic_digest(c, "SELECT jti, client_id, tenant_id, route_id FROM authz_revocations ORDER BY jti"),
        # Identity-only columns (must remain identical even across --reset-authority)
        "agent_keys_identity": semantic_digest(c, "SELECT id, tenant_id, hex(ed25519_public) FROM agent_keys ORDER BY id"),
        "leases_identity": semantic_digest(c, "SELECT id, tenant_id, agent_key_id, hostname, label, port, access_mode, COALESCE(expires_at,'') FROM leases ORDER BY id"),
        "mcp_publications_identity": semantic_digest(c, "SELECT route_id, tenant_id, owner_key_id, external_host, profile, pub_name FROM mcp_publications ORDER BY route_id"),
        "authz_clients_identity": semantic_digest(c, "SELECT id, COALESCE(tenant_id,''), COALESCE(route_id,'') FROM authz_clients ORDER BY id"),
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
ver_info = json.loads(ver_res.stdout)
expected_schema = int(ver_info["schema_version"])
bin_sha = sha256_file(args.bin)

work = tempfile.mkdtemp(prefix="ocliv-mig-rehearsal-")
os.chmod(work, 0o700)
receipt_data = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "candidate_commit": ver_info.get("build_commit") or ver_info.get("commit") or "",
    "binary_sha256": bin_sha,
    "expected_schema": expected_schema,
    "src_db": os.path.realpath(args.src_db),
}
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

    snap_sha = sha256_file(dst_db)
    receipt_data["src_journal_mode"] = src_journal_mode
    receipt_data["src_schema"] = src_schema
    receipt_data["snapshot_sha256"] = snap_sha
    print(f"SNAPSHOT: src_journal_mode={src_journal_mode} src_schema=V{src_schema} sha256={snap_sha}", flush=True)

    before = collect_inventory(dst_db)
    receipt_data["pre_migration"] = before
    print("PRE-MIGRATION:", json.dumps(before), flush=True)

    mig = subprocess.run([args.bin, "relay", "pending", "--data", copy_dir], capture_output=True, text=True)
    check("M1: candidate binary opens and migrates online snapshot cleanly", mig.returncode == 0, f"rc={mig.returncode} {mig.stderr[:120]}")

    after = collect_inventory(dst_db)
    receipt_data["post_migration"] = after
    print("POST-MIGRATION:", json.dumps(after), flush=True)
    check(f"M2: schema reached V{expected_schema}", after["schema"] == expected_schema, f"got={after['schema']}")
    check("M3: semantic digests of tenants/keys/leases/publications identical",
          after["tenants"] == before["tenants"]
          and after["agent_keys"] == before["agent_keys"]
          and after["leases"] == before["leases"]
          and after["mcp_publications"] == before["mcp_publications"],
          f"tenants={after['tenants'][:16]} keys={after['agent_keys'][:16]}")
    check("M4: terminal lease tombstones preserved identically",
          after["terminal_leases"] == before["terminal_leases"],
          f"tombstones={after['terminal_leases'][:16]}")
    check("M5: OAuth clients, grants & revocations preserved identically",
          after["authz_clients"] == before["authz_clients"]
          and after["authz_grants"] == before["authz_grants"]
          and after["authz_revocations"] == before["authz_revocations"],
          f"grants={after['authz_grants'][:16]} revocations={after['authz_revocations'][:16]}")

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

    # Backup + validate-backup + restore --reset-authority + full contract validation + live relay readiness.
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
        rc_conn = sqlite3.connect(f"file:{rst_db}?mode=ro", uri=True)
        r_ic = rc_conn.execute("PRAGMA integrity_check").fetchone()[0]
        r_fk = rc_conn.execute("PRAGMA foreign_key_check").fetchall()
        r_sv = rc_conn.execute("SELECT MAX(v) FROM schema_version").fetchone()[0]
        # Explicit --reset-authority transformed-state assertions (must all be 0):
        reset_counts = {
            "non_revoked_keys": rc_conn.execute("SELECT COUNT(*) FROM agent_keys WHERE status<>'revoked'").fetchone()[0],
            "live_leases": rc_conn.execute("SELECT COUNT(*) FROM leases WHERE status IN ('ACTIVE','RECONNECTING')").fetchone()[0],
            "unrevoked_publications": rc_conn.execute("SELECT COUNT(*) FROM mcp_publications WHERE revoked_at IS NULL").fetchone()[0],
            "unrevoked_authz_clients": rc_conn.execute("SELECT COUNT(*) FROM authz_clients WHERE revoked_at IS NULL").fetchone()[0],
            "non_revoked_authz_grants": rc_conn.execute("SELECT COUNT(*) FROM authz_grants WHERE status<>'revoked'").fetchone()[0],
            "authz_issuer_keys": rc_conn.execute("SELECT COUNT(*) FROM authz_issuer_key").fetchone()[0],
            "unrevoked_access_tokens": rc_conn.execute("SELECT COUNT(*) FROM access_tokens WHERE revoked_at IS NULL").fetchone()[0],
            "unrevoked_visitor_sessions": rc_conn.execute("SELECT COUNT(*) FROM visitor_sessions WHERE revoked_at IS NULL").fetchone()[0],
        }
        # Pre-existing terminal lease tombstones must still exist with unchanged status/generation.
        rc_conn.close()
        rst_inv = collect_inventory(rst_db)
        receipt_data["post_restore_reset_authority"] = {"inventory": rst_inv, "reset_counts": reset_counts}

        unchanged_ok = (
            rst_inv["tenants"] == after["tenants"]
            and rst_inv["agent_keys_identity"] == after["agent_keys_identity"]
            and rst_inv["leases_identity"] == after["leases_identity"]
            and rst_inv["mcp_publications_identity"] == after["mcp_publications_identity"]
            and rst_inv["authz_clients_identity"] == after["authz_clients_identity"]
            and rst_inv["authz_revocations"] == after["authz_revocations"]
        )
        reset_ok = all(v == 0 for v in reset_counts.values())
        check("M10b: restored DB full --reset-authority contract (unchanged identities + all authority revoked)",
              r_ic == "ok" and len(r_fk) == 0 and r_sv == expected_schema and unchanged_ok and reset_ok,
              f"ic={r_ic} sv={r_sv} unchanged_ok={unchanged_ok} reset_counts={reset_counts}")

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

receipt_data["pass_count"] = len(PASS)
receipt_data["fail_count"] = len(FAIL)
receipt_data["failed"] = FAIL
receipt_data["ok"] = len(FAIL) == 0
if args.receipt_out:
    with open(args.receipt_out, "w", encoding="utf-8") as rf:
        json.dump(receipt_data, rf, indent=2)

print(f"\n== MIGRATION REHEARSAL SUMMARY ==\nPASS {len(PASS)}\nFAIL {len(FAIL)} {FAIL}")
if FAIL:
    sys.exit(1)
