#!/usr/bin/env python3
"""Mechanically verify all five production promotion receipts agree on one exact candidate.

Enforces ONE canonical 6-field release identity across ALL FIVE receipts:
  - candidate_commit
  - binary_sha256 (normalized from qual_binary_sha256 on qualification receipt)
  - manifest_sha256
  - release_sequence
  - signing_key_id
  - sbom_actual_sha256

And enforces gate-specific operational invariants for every receipt:
  1. Strict qualification (`--qual`): mode == 'strict-production', ok == True,
     skip_count == 0, fail_count == 0, ephemeral_state_retained == False,
     scratch_cleanup_ok == True, sbom_actual_sha256 == sbom_declared_sha256,
     sbom_generator == 'cyclonedx-gomod'.
  2. Production migration rehearsal (`--migration`): production_gate == True,
     non-empty source_db_realpath, ok == True, fail_count == 0,
     scratch_cleanup_ok == True, scratch_retained == False.
  3. 24-hour release-gate soak (`--soak`): release_gate == True, ok == True,
     duration_sec >= 86400, scratch_cleanup_ok == True, scratch_retained == False,
     recovery_required_at_end == False.
  4. Off-LAN trusted-TLS (`--offlan-tls`): receipt_type == 'offlan-trusted-tls',
     receipt_version == 1, ok == True, system_trust_verified == True,
     insecure_tls_disabled == True, off_lan == True, hostname_verified == True,
     wildcard_lease_verified == True.
  5. Official ChatGPT OAuth (`--chatgpt-oauth`): receipt_type == 'chatgpt-oauth-e2e',
     receipt_version == 1, ok == True, official_chatgpt_client == True,
     public_trusted_tls_endpoint == True, authorization_completed == True,
     tools_list_succeeded == True, tools_call_succeeded == True,
     refresh_reconnect_succeeded == True, revocation_succeeded == True,
     bearer_forwarding_blocked == True.

Usage:
  verify-promotion-evidence.py \
      --qual qual-receipt.json \
      --migration mig-receipt.json \
      --soak soak-24h-receipt.json \
      --offlan-tls offlan-tls-receipt.json \
      --chatgpt-oauth chatgpt-oauth-receipt.json
  verify-promotion-evidence.py --self-test
"""
import argparse, json, sys

RELEASE_IDENTITY_FIELDS = (
    "candidate_commit",
    "binary_sha256",
    "manifest_sha256",
    "release_sequence",
    "signing_key_id",
    "sbom_actual_sha256",
)

OFFLAN_TLS_REQUIRED_BOOLS = (
    "ok",
    "system_trust_verified",
    "insecure_tls_disabled",
    "off_lan",
    "hostname_verified",
    "wildcard_lease_verified",
)

CHATGPT_OAUTH_REQUIRED_BOOLS = (
    "ok",
    "official_chatgpt_client",
    "public_trusted_tls_endpoint",
    "authorization_completed",
    "tools_list_succeeded",
    "tools_call_succeeded",
    "refresh_reconnect_succeeded",
    "revocation_succeeded",
    "bearer_forwarding_blocked",
)


def verify_receipts(qual, mig, soak, tls, oauth):
    errors = []

    # Normalize qual_binary_sha256 -> binary_sha256 on qualification receipt.
    q_norm = dict(qual)
    if not q_norm.get("binary_sha256") and q_norm.get("qual_binary_sha256"):
        q_norm["binary_sha256"] = q_norm["qual_binary_sha256"]

    # 1. Strict qualification gate
    if q_norm.get("mode") != "strict-production":
        errors.append(f"qual: mode={q_norm.get('mode')!r}, want 'strict-production'")
    if q_norm.get("ok") is not True:
        errors.append(f"qual: ok={q_norm.get('ok')!r}")
    if q_norm.get("skip_count") != 0 or q_norm.get("fail_count") != 0:
        errors.append(f"qual: skip={q_norm.get('skip_count')} fail={q_norm.get('fail_count')}")
    if q_norm.get("ephemeral_state_retained") is not False:
        errors.append("qual: ephemeral_state_retained must be false")
    if q_norm.get("scratch_cleanup_ok") is not True:
        errors.append("qual: scratch_cleanup_ok must be true")
    if not q_norm.get("sbom_actual_sha256") or q_norm.get("sbom_actual_sha256") != q_norm.get("sbom_declared_sha256"):
        errors.append("qual: SBOM actual/declared SHA-256 missing or mismatched")
    if q_norm.get("sbom_generator") != "cyclonedx-gomod":
        errors.append(f"qual: sbom_generator={q_norm.get('sbom_generator')!r}, want 'cyclonedx-gomod'")
    if q_norm.get("signed_artifact_sha256") != q_norm.get("binary_sha256"):
        errors.append("qual: signed_artifact_sha256 != binary_sha256")

    # Canonical 6-field release identity must be present and non-empty in qual and IDENTICAL across all 5 receipts.
    canonical = {}
    for field in RELEASE_IDENTITY_FIELDS:
        val = q_norm.get(field)
        if val in (None, "", 0) or isinstance(val, bool):
            errors.append(f"qual: missing or invalid canonical identity field {field!r}")
        canonical[field] = val

    for label, doc in (("migration", mig), ("soak", soak), ("offlan-tls", tls), ("chatgpt-oauth", oauth)):
        for field in RELEASE_IDENTITY_FIELDS:
            got = doc.get(field)
            if got in (None, "", 0) or isinstance(got, bool):
                errors.append(f"{label}: missing required release identity field {field!r}")
            elif got != canonical[field]:
                errors.append(f"{label}: {field}={got!r} != qual {canonical[field]!r}")

    # 2. Production migration rehearsal gate
    if mig.get("production_gate") is not True:
        errors.append(f"migration: production_gate={mig.get('production_gate')!r}, want True")
    if not mig.get("source_db_realpath"):
        errors.append("migration: missing source_db_realpath")
    if mig.get("ok") is not True or mig.get("fail_count") != 0:
        errors.append(f"migration: ok={mig.get('ok')} fail_count={mig.get('fail_count')}")
    if mig.get("scratch_cleanup_ok") is not True or mig.get("scratch_retained") is not False:
        errors.append("migration: scratch cleanup not verified")

    # 3. 24-hour release-gate soak
    if soak.get("ok") is not True or soak.get("release_gate") is not True:
        errors.append(f"soak: ok={soak.get('ok')} release_gate={soak.get('release_gate')}")
    if (soak.get("duration_sec") or 0) < 86400:
        errors.append(f"soak: duration_sec={soak.get('duration_sec')} < 86400")
    if soak.get("scratch_cleanup_ok") is not True or soak.get("scratch_retained") is not False:
        errors.append("soak: scratch cleanup not verified")
    if (soak.get("counts") or {}).get("recovery_required_at_end") is not False:
        errors.append("soak: recovery_required_at_end must be false")

    # 4. Off-LAN trusted TLS (versioned schema + operational assertions)
    if tls.get("receipt_type") != "offlan-trusted-tls" or tls.get("receipt_version") != 1:
        errors.append(f"offlan-tls: invalid receipt_type/version ({tls.get('receipt_type')!r}, {tls.get('receipt_version')!r})")
    for b in OFFLAN_TLS_REQUIRED_BOOLS:
        if tls.get(b) is not True:
            errors.append(f"offlan-tls: {b} must be true (got {tls.get(b)!r})")

    # 5. Official ChatGPT OAuth (versioned schema + operational assertions)
    if oauth.get("receipt_type") != "chatgpt-oauth-e2e" or oauth.get("receipt_version") != 1:
        errors.append(f"chatgpt-oauth: invalid receipt_type/version ({oauth.get('receipt_type')!r}, {oauth.get('receipt_version')!r})")
    for b in CHATGPT_OAUTH_REQUIRED_BOOLS:
        if oauth.get(b) is not True:
            errors.append(f"chatgpt-oauth: {b} must be true (got {oauth.get(b)!r})")

    return errors, canonical


def run_self_test():
    ident = {
        "candidate_commit": "abc123",
        "binary_sha256": "11" * 32,
        "manifest_sha256": "22" * 32,
        "release_sequence": 267,
        "signing_key_id": "prod-key-2026-v1",
        "sbom_actual_sha256": "33" * 32,
    }
    qual = dict(ident, mode="strict-production", ok=True, skip_count=0, fail_count=0,
                ephemeral_state_retained=False, scratch_cleanup_ok=True,
                sbom_declared_sha256="33" * 32, sbom_generator="cyclonedx-gomod",
                signed_artifact_sha256="11" * 32)
    mig = dict(ident, production_gate=True, source_db_realpath="/var/lib/ocliv/ocliv.db",
               ok=True, fail_count=0, scratch_cleanup_ok=True, scratch_retained=False)
    soak = dict(ident, release_gate=True, ok=True, duration_sec=86400,
                scratch_cleanup_ok=True, scratch_retained=False,
                counts={"recovery_required_at_end": False})
    tls = dict(ident, receipt_type="offlan-trusted-tls", receipt_version=1,
               **{b: True for b in OFFLAN_TLS_REQUIRED_BOOLS})
    oauth = dict(ident, receipt_type="chatgpt-oauth-e2e", receipt_version=1,
                 **{b: True for b in CHATGPT_OAUTH_REQUIRED_BOOLS})

    errs, _ = verify_receipts(qual, mig, soak, tls, oauth)
    assert not errs, f"valid 5-receipt tuple should pass, got: {errs}"

    # Missing signing_key_id in migration must fail.
    bad_mig = dict(mig)
    bad_mig.pop("signing_key_id")
    assert verify_receipts(qual, bad_mig, soak, tls, oauth)[0], "missing identity field must fail"

    # Unbound staging migration (production_gate=False) must fail.
    assert verify_receipts(qual, dict(mig, production_gate=False), soak, tls, oauth)[0], "production_gate=False must fail"

    # Weak TLS receipt (missing wildcard_lease_verified) must fail.
    assert verify_receipts(qual, mig, soak, dict(tls, wildcard_lease_verified=False), oauth)[0], "incomplete TLS receipt must fail"

    # Weak OAuth receipt (missing bearer_forwarding_blocked) must fail.
    assert verify_receipts(qual, mig, soak, tls, dict(oauth, bearer_forwarding_blocked=False))[0], "incomplete OAuth receipt must fail"

    print("VERIFY_PROMOTION_SELF_TEST=OK")


def main():
    parser = argparse.ArgumentParser(description="Verify mechanical agreement across all Ocliv production promotion receipts")
    parser.add_argument("--qual", default="", help="Strict qualification JSON receipt")
    parser.add_argument("--migration", default="", help="Production-gate online-snapshot migration rehearsal JSON receipt")
    parser.add_argument("--soak", default="", help="24-hour release-gate soak JSON receipt")
    parser.add_argument("--offlan-tls", default="", help="Off-LAN trusted-TLS acceptance JSON receipt")
    parser.add_argument("--chatgpt-oauth", default="", help="Official ChatGPT OAuth acceptance JSON receipt")
    parser.add_argument("--self-test", action="store_true", help="Run deterministic verifier self-tests and exit")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        sys.exit(0)

    for flag, val in (("--qual", args.qual), ("--migration", args.migration), ("--soak", args.soak),
                      ("--offlan-tls", args.offlan_tls), ("--chatgpt-oauth", args.chatgpt_oauth)):
        if not val:
            raise SystemExit(f"error: {flag} is required")

    def load_json(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    errors, canonical = verify_receipts(
        load_json(args.qual),
        load_json(args.migration),
        load_json(args.soak),
        load_json(args.offlan_tls),
        load_json(args.chatgpt_oauth),
    )
    if errors:
        print("PROMOTION EVIDENCE VERIFICATION FAILED:", file=sys.stderr)
        for e in errors:
            print("  -", e, file=sys.stderr)
        sys.exit(1)

    print(
        f"PROMOTION EVIDENCE VERIFIED: commit={canonical['candidate_commit']} "
        f"binary_sha256={canonical['binary_sha256']} manifest_sha256={canonical['manifest_sha256']} "
        f"release_sequence={canonical['release_sequence']} signing_key_id={canonical['signing_key_id']} "
        f"sbom_actual_sha256={canonical['sbom_actual_sha256']}"
    )


if __name__ == "__main__":
    main()
