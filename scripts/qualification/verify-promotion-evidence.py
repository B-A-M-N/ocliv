#!/usr/bin/env python3
"""Mechanically verify all five production promotion receipts agree on one exact candidate.

Verifies:
  1. Strict qualification receipt (`--qual`): mode == 'strict-production', ok == True,
     skip_count == 0, ephemeral_state_retained == False, scratch_cleanup_ok == True,
     non-empty SBOM actual == declared SHA-256, cyclonedx-gomod generator.
  2. Online-snapshot migration rehearsal receipt (`--migration`): ok == True, fail_count == 0,
     scratch_cleanup_ok == True, scratch_retained == False, commit & binary SHA-256 match.
  3. 24-hour release-gate soak receipt (`--soak`): ok == True, release_gate == True,
     duration_sec >= 86400, scratch_cleanup_ok == True, scratch_retained == False,
     recovery_required_at_end == False, commit & binary SHA-256 match.
  4. Off-LAN trusted-TLS receipt (`--offlan-tls`): ok == True, commit & binary SHA-256 match.
  5. Official ChatGPT OAuth receipt (`--chatgpt-oauth`): ok == True, commit & binary SHA-256 match.

Usage:
  verify-promotion-evidence.py \
      --qual qual-receipt.json \
      --migration mig-receipt.json \
      --soak soak-24h-receipt.json \
      --offlan-tls offlan-tls-receipt.json \
      --chatgpt-oauth chatgpt-oauth-receipt.json
"""
import argparse, json, sys

parser = argparse.ArgumentParser(description="Verify mechanical agreement across all Ocliv production promotion receipts")
parser.add_argument("--qual", required=True, help="Strict qualification JSON receipt")
parser.add_argument("--migration", required=True, help="Live-production online-snapshot migration rehearsal JSON receipt")
parser.add_argument("--soak", required=True, help="24-hour release-gate soak JSON receipt")
parser.add_argument("--offlan-tls", required=True, help="Off-LAN trusted-TLS acceptance JSON receipt")
parser.add_argument("--chatgpt-oauth", required=True, help="Official ChatGPT OAuth acceptance JSON receipt")
args = parser.parse_args()


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


errors = []

qual = load_json(args.qual)
mig = load_json(args.migration)
soak = load_json(args.soak)
tls = load_json(args.offlan_tls)
oauth = load_json(args.chatgpt_oauth)

# 1. Strict qualification gate
if qual.get("mode") != "strict-production":
    errors.append(f"qual: mode={qual.get('mode')!r}, want 'strict-production'")
if qual.get("ok") is not True:
    errors.append(f"qual: ok={qual.get('ok')!r}")
if qual.get("skip_count") != 0 or qual.get("fail_count") != 0:
    errors.append(f"qual: skip={qual.get('skip_count')} fail={qual.get('fail_count')}")
if qual.get("ephemeral_state_retained") is not False:
    errors.append("qual: ephemeral_state_retained must be false")
if qual.get("scratch_cleanup_ok") is not True:
    errors.append("qual: scratch_cleanup_ok must be true")
if not qual.get("sbom_actual_sha256") or qual.get("sbom_actual_sha256") != qual.get("sbom_declared_sha256"):
    errors.append("qual: SBOM actual/declared SHA-256 missing or mismatched")
if qual.get("sbom_generator") != "cyclonedx-gomod":
    errors.append(f"qual: sbom_generator={qual.get('sbom_generator')!r}, want 'cyclonedx-gomod'")

commit = qual.get("candidate_commit", "")
bin_sha = qual.get("qual_binary_sha256", "")
manifest_sha = qual.get("manifest_sha256", "")
rel_seq = qual.get("release_sequence")
if not commit or not bin_sha or not manifest_sha or not rel_seq:
    errors.append("qual: missing core provenance (commit/binary_sha256/manifest_sha256/release_sequence)")
if qual.get("signed_artifact_sha256") != bin_sha:
    errors.append("qual: signed_artifact_sha256 != qual_binary_sha256")

# 2. Migration rehearsal gate
if mig.get("ok") is not True or mig.get("fail_count") != 0:
    errors.append(f"migration: ok={mig.get('ok')} fail_count={mig.get('fail_count')}")
if mig.get("scratch_cleanup_ok") is not True or mig.get("scratch_retained") is not False:
    errors.append("migration: scratch cleanup not verified")
if mig.get("candidate_commit") != commit or mig.get("binary_sha256") != bin_sha:
    errors.append("migration: candidate_commit/binary_sha256 mismatch with qual receipt")
if mig.get("manifest_sha256") and mig.get("manifest_sha256") != manifest_sha:
    errors.append("migration: manifest_sha256 mismatch with qual receipt")

# 3. 24-hour release-gate soak
if soak.get("ok") is not True or soak.get("release_gate") is not True:
    errors.append(f"soak: ok={soak.get('ok')} release_gate={soak.get('release_gate')}")
if (soak.get("duration_sec") or 0) < 86400:
    errors.append(f"soak: duration_sec={soak.get('duration_sec')} < 86400")
if soak.get("scratch_cleanup_ok") is not True or soak.get("scratch_retained") is not False:
    errors.append("soak: scratch cleanup not verified")
if (soak.get("counts") or {}).get("recovery_required_at_end") is not False:
    errors.append("soak: recovery_required_at_end must be false")
if soak.get("candidate_commit") != commit or soak.get("binary_sha256") != bin_sha:
    errors.append("soak: candidate_commit/binary_sha256 mismatch with qual receipt")
if soak.get("manifest_sha256") != manifest_sha or soak.get("release_sequence") != rel_seq:
    errors.append("soak: manifest_sha256/release_sequence mismatch with qual receipt")

# 4. Off-LAN trusted TLS & 5. Official ChatGPT OAuth
for label, doc in (("offlan-tls", tls), ("chatgpt-oauth", oauth)):
    if doc.get("ok") is not True:
        errors.append(f"{label}: ok={doc.get('ok')!r}")
    if doc.get("candidate_commit") != commit:
        errors.append(f"{label}: candidate_commit={doc.get('candidate_commit')!r} != {commit!r}")
    doc_sha = doc.get("binary_sha256") or doc.get("qual_binary_sha256") or ""
    if doc_sha != bin_sha:
        errors.append(f"{label}: binary_sha256={doc_sha!r} != {bin_sha!r}")

if errors:
    print("PROMOTION EVIDENCE VERIFICATION FAILED:", file=sys.stderr)
    for e in errors:
        print("  -", e, file=sys.stderr)
    sys.exit(1)

print(
    f"PROMOTION EVIDENCE VERIFIED: commit={commit} binary_sha256={bin_sha} "
    f"manifest_sha256={manifest_sha} release_sequence={rel_seq} signing_key_id={qual.get('signing_key_id')}"
)
