#!/usr/bin/env python3
"""Production-copy schema migration rehearsal using SQLite's online backup API.

Takes a transactionally consistent read-only online snapshot of a source SQLite
database (never copying raw -wal/-shm files independently), migrates the
snapshot with the candidate `ocliv` binary, verifies SQLite integrity, foreign
keys, full 64-hex canonical semantic digests of security-critical authority
columns, legacy pairing expiration, and full backup/validate/restore with the
first-class `--reset-authority` mutation contract + live relay readiness.

Fail-closed scratch cleanup: verifies complete removal of the temporary
directory containing the copied DB before writing a PASS receipt.

NEVER mutates the source database or touches any running production relay.

Usage:
  rehearse-prod-migration.py --bin /path/to/ocliv --src-db /path/to/ocliv.db \
      [--qualification-receipt qual-receipt.json] [--receipt-out mig-receipt.json]
"""
import argparse, datetime, hashlib, json, os, shutil, socket, sqlite3, subprocess, sys, tempfile, time
import urllib.request

parser = argparse.ArgumentParser(description="Ocliv transactionally consistent migration rehearsal")
parser.add_argument("--bin", required=True, help="Path to candidate ocliv binary")
parser.add_argument("--src-db", required=True, help="Path to source ocliv.db (read-only online snapshot)")
parser.add_argument("--qualification-receipt", default="", help="Strict qualification receipt JSON to bind candidate provenance (required with --production-gate)")
parser.add_argument("--expected-source-db", default="", help="Expected realpath of production source DB (required with --production-gate, e.g. /var/lib/ocliv/ocliv.db)")
parser.add_argument("--production-gate", action="store_true", help="Enforce production migration gate (requires --qualification-receipt, --expected-source-db, --receipt-out)")
parser.add_argument("--receipt-out", default="", help="Path to write provenance-bound JSON receipt (required with --production-gate)")
args = parser.parse_args()

if args.production_gate:
    if not args.qualification_receipt:
        raise SystemExit("--production-gate requires --qualification-receipt PATH")
    if not args.expected_source_db:
        raise SystemExit("--production-gate requires --expected-source-db PATH (e.g. /var/lib/ocliv/ocliv.db)")
    if not args.receipt_out:
        raise SystemExit("--production-gate requires --receipt-out PATH")
    if os.path.realpath(args.src_db) != os.path.realpath(args.expected_source_db):
        raise SystemExit(
            f"--production-gate source DB mismatch: src={os.path.realpath(args.src_db)} != expected={os.path.realpath(args.expected_source_db)}"
        )

PASS, FAIL = [], []

# First-class --reset-authority transformation contract (versioned for auditability).
RESET_CONTRACT_VERSION = 1

INVENTORY_QUERIES = {
    "tenants": ("tenants", "SELECT id, status, quotas_json FROM tenants ORDER BY id"),
    "agent_keys": ("agent_keys", "SELECT id, tenant_id, hex(ed25519_public), status, COALESCE(revoked_at,'') FROM agent_keys ORDER BY id"),
    "leases": ("leases", "SELECT id, tenant_id, agent_key_id, hostname, label, port, access_mode, status, COALESCE(expires_at,'') FROM leases ORDER BY id"),
    "terminal_leases": ("leases", "SELECT id, status, generation, token_generation FROM leases WHERE status IN ('CLOSED','EXPIRED','REVOKED') ORDER BY id"),
    "mcp_publications": ("mcp_publications", "SELECT route_id, tenant_id, owner_key_id, external_host, profile, pub_name, COALESCE(revoked_at,'') FROM mcp_publications ORDER BY route_id"),
    "authz_clients": ("authz_clients", "SELECT id, COALESCE(tenant_id,''), COALESCE(route_id,''), COALESCE(revoked_at,'') FROM authz_clients ORDER BY id"),
    "authz_grants": ("authz_grants", "SELECT client_id, tenant_id, route_id, status FROM authz_grants ORDER BY client_id, tenant_id, route_id"),
    "authz_revocations": ("authz_revocations", "SELECT jti, client_id, tenant_id, route_id FROM authz_revocations ORDER BY jti"),
    "agent_keys_identity": ("agent_keys", "SELECT id, tenant_id, hex(ed25519_public) FROM agent_keys ORDER BY id"),
    "leases_identity": ("leases", "SELECT id, tenant_id, agent_key_id, hostname, label, port, access_mode, COALESCE(expires_at,'') FROM leases ORDER BY id"),
    "mcp_publications_identity": ("mcp_publications", "SELECT route_id, tenant_id, owner_key_id, external_host, profile, pub_name FROM mcp_publications ORDER BY route_id"),
    "authz_clients_identity": ("authz_clients", "SELECT id, COALESCE(tenant_id,''), COALESCE(route_id,'') FROM authz_clients ORDER BY id"),
}

MUST_PRESERVE = (
    "tenants",
    "agent_keys_identity",
    "leases_identity",
    "mcp_publications_identity",
    "authz_clients_identity",
    "authz_revocations",
)

RESET_TO_ZERO = {
    "non_revoked_keys": "SELECT COUNT(*) FROM agent_keys WHERE status<>'revoked'",
    "live_leases": "SELECT COUNT(*) FROM leases WHERE status IN ('ACTIVE','RECONNECTING')",
    "unrevoked_publications": "SELECT COUNT(*) FROM mcp_publications WHERE revoked_at IS NULL",
    "unrevoked_authz_clients": "SELECT COUNT(*) FROM authz_clients WHERE revoked_at IS NULL",
    "non_revoked_authz_grants": "SELECT COUNT(*) FROM authz_grants WHERE status<>'revoked'",
    "authz_issuer_keys": "SELECT COUNT(*) FROM authz_issuer_key",
    "unrevoked_access_tokens": "SELECT COUNT(*) FROM access_tokens WHERE revoked_at IS NULL",
    "unrevoked_visitor_sessions": "SELECT COUNT(*) FROM visitor_sessions WHERE revoked_at IS NULL",
}


def check(name, ok, note=""):
    (PASS if ok else FAIL).append(name)
    print(("[PASS]" if ok else "[FAIL]"), name, note, flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def table_exists(conn, table):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def semantic_digest(conn, table, sql, allow_absent=False):
    """Return full 64-hex canonical sorted SHA-256 digest of security-critical rows."""
    if not table_exists(conn, table):
        if allow_absent:
            return "TABLE_ABSENT"
        raise RuntimeError(f"required table {table!r} is absent from database")
    rows = conn.execute(sql).fetchall()
    canon = "\n".join(json.dumps(list(r), separators=(",", ":")) for r in rows)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest() + f"(n={len(rows)})"


def collect_inventory(db_path, allow_absent=False):
    c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        inv = {"schema": c.execute("SELECT MAX(v) FROM schema_version").fetchone()[0]}
        for key, (table, sql) in INVENTORY_QUERIES.items():
            inv[key] = semantic_digest(c, table, sql, allow_absent=allow_absent)
        return inv
    finally:
        c.close()


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
cand_commit = ver_info.get("build_commit") or ver_info.get("commit") or ""
expected_schema = int(ver_info["schema_version"])
bin_sha = sha256_file(args.bin)

bound_provenance = {}
if args.qualification_receipt:
    with open(args.qualification_receipt, encoding="utf-8") as qf:
        qr = json.load(qf)
    errs = []
    if qr.get("mode") != "strict-production":
        errs.append(f"mode={qr.get('mode')!r} != 'strict-production'")
    if qr.get("ok") is not True:
        errs.append(f"ok={qr.get('ok')!r}")
    if qr.get("skip_count") != 0:
        errs.append(f"skip_count={qr.get('skip_count')!r}")
    if qr.get("ephemeral_state_retained") is not False:
        errs.append(f"ephemeral_state_retained={qr.get('ephemeral_state_retained')!r}")
    if qr.get("candidate_commit") != cand_commit:
        errs.append(f"commit mismatch: receipt={qr.get('candidate_commit')} bin={cand_commit}")
    if qr.get("qual_binary_sha256") != bin_sha:
        errs.append(f"binary sha256 mismatch: receipt={qr.get('qual_binary_sha256')} bin={bin_sha}")
    if errs:
        raise SystemExit("FAIL: --qualification-receipt validation failed: " + "; ".join(errs))
    bound_provenance = {
        "qualification_receipt": os.path.realpath(args.qualification_receipt),
        "manifest_sha256": qr.get("manifest_sha256", ""),
        "release_sequence": qr.get("release_sequence"),
        "signing_key_id": qr.get("signing_key_id", ""),
        "sbom_actual_sha256": qr.get("sbom_actual_sha256", ""),
    }

work = tempfile.mkdtemp(prefix="ocliv-mig-rehearsal-")
os.chmod(work, 0o700)
receipt_data = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "production_gate": bool(args.production_gate),
    "reset_contract_version": RESET_CONTRACT_VERSION,
    "candidate_commit": cand_commit,
    "binary_sha256": bin_sha,
    "expected_schema": expected_schema,
    "src_db": os.path.realpath(args.src_db),
    "source_db_realpath": os.path.realpath(args.src_db),
}
receipt_data.update(bound_provenance)

cleanup_ok = False
cleanup_err = ""
try:
    copy_dir = os.path.join(work, "data")
    os.makedirs(copy_dir, mode=0o700)
    dst_db = os.path.join(copy_dir, "ocliv.db")

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

    before = collect_inventory(dst_db, allow_absent=(src_schema < expected_schema))
    receipt_data["pre_migration"] = before
    print("PRE-MIGRATION:", json.dumps(before), flush=True)

    mig = subprocess.run([args.bin, "relay", "pending", "--data", copy_dir], capture_output=True, text=True)
    check("M1: candidate binary opens and migrates online snapshot cleanly", mig.returncode == 0, f"rc={mig.returncode} {mig.stderr[:120]}")

    after = collect_inventory(dst_db, allow_absent=False)
    receipt_data["post_migration"] = after
    print("POST-MIGRATION:", json.dumps(after), flush=True)
    check(f"M2: schema reached V{expected_schema} with all required tables present",
          after["schema"] == expected_schema and all(v != "TABLE_ABSENT" for v in after.values()),
          f"got={after['schema']}")
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
        reset_counts = {name: rc_conn.execute(sql).fetchone()[0] for name, sql in RESET_TO_ZERO.items()}
        rc_conn.close()
        rst_inv = collect_inventory(rst_db, allow_absent=False)
        preserved_diffs = [k for k in MUST_PRESERVE if rst_inv[k] != after[k]]
        receipt_data["post_restore_reset_authority"] = {
            "reset_contract_version": RESET_CONTRACT_VERSION,
            "inventory": rst_inv,
            "preserved_diffs": preserved_diffs,
            "reset_counts": reset_counts,
        }

        unchanged_ok = len(preserved_diffs) == 0
        reset_ok = all(v == 0 for v in reset_counts.values())
        check("M10b: restored DB full --reset-authority contract (unchanged identities + all authority revoked)",
              r_ic == "ok" and len(r_fk) == 0 and r_sv == expected_schema and unchanged_ok and reset_ok,
              f"ic={r_ic} sv={r_sv} preserved_diffs={preserved_diffs} reset_counts={reset_counts}")

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
    # Fail-closed scratch cleanup: prove removal without ignore_errors.
    try:
        shutil.rmtree(work)
        cleanup_ok = not os.path.exists(work)
    except Exception as exc:
        cleanup_ok = False
        cleanup_err = str(exc)

if not cleanup_ok:
    check("M11: fail-closed scratch directory removal", False, f"work={work} err={cleanup_err}")

receipt_data["scratch_cleanup_ok"] = cleanup_ok
receipt_data["scratch_retained"] = not cleanup_ok
receipt_data["pass_count"] = len(PASS)
receipt_data["fail_count"] = len(FAIL)
receipt_data["failed"] = FAIL
receipt_data["ok"] = (len(FAIL) == 0) and cleanup_ok
if args.receipt_out:
    with open(args.receipt_out, "w", encoding="utf-8") as rf:
        json.dump(receipt_data, rf, indent=2)

print(f"\n== MIGRATION REHEARSAL SUMMARY ==\nPASS {len(PASS)}\nFAIL {len(FAIL)} {FAIL}")
if FAIL or not cleanup_ok:
    sys.exit(1)
