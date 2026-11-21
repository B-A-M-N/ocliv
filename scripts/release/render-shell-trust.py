#!/usr/bin/env python3
"""Render or check the generated trusted-key block in packaging/install/install-client.sh
from the single canonical source internal/installer/release-trust.json.

Usage:
  render-shell-trust.py          # updates packaging/install/install-client.sh in place
  render-shell-trust.py --check  # exits non-zero if install-client.sh is out of sync
"""
import argparse, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TRUST_JSON = ROOT / "internal" / "installer" / "release-trust.json"
SHELL_SCRIPT = ROOT / "packaging" / "install" / "install-client.sh"

BEGIN_MARK = "# BEGIN GENERATED TRUST ROOT (from internal/installer/release-trust.json)"
END_MARK = "# END GENERATED TRUST ROOT"


def render_block(trust_path: pathlib.Path) -> str:
    data = json.loads(trust_path.read_text(encoding="utf-8"))
    keys = data.get("keys") or []
    if not keys:
        raise ValueError("release-trust.json contains no keys")
    lines = []
    for k in keys:
        kid = str(k["id"]).strip()
        kst = str(k["status"]).strip()
        khex = str(k["ed25519"]).strip().lower()
        if not kid or kst not in ("active", "retiring", "revoked") or len(khex) != 64:
            raise ValueError(f"invalid key entry in release-trust.json: {k}")
        if "|" in kid or "\n" in kid or "'" in kid:
            raise ValueError(f"unsafe characters in key id: {kid!r}")
        lines.append(f"{kid}|{kst}|{khex}")
    joined = "\n".join(lines)
    return f"{BEGIN_MARK}\nTRUSTED_RELEASE_KEYS='{joined}'\n{END_MARK}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if install-client.sh differs from release-trust.json")
    args = parser.parse_args()

    want_block = render_block(TRUST_JSON)
    content = SHELL_SCRIPT.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(BEGIN_MARK) + r".*?" + re.escape(END_MARK), re.DOTALL)
    if not pattern.search(content):
        print(f"error: missing generated trust markers in {SHELL_SCRIPT}", file=sys.stderr)
        return 1
    updated = pattern.sub(want_block, content, count=1)
    if args.check:
        if updated != content:
            print("error: packaging/install/install-client.sh trust root is out of sync with internal/installer/release-trust.json", file=sys.stderr)
            print("       run: python3 scripts/release/render-shell-trust.py", file=sys.stderr)
            return 1
        return 0
    if updated != content:
        SHELL_SCRIPT.write_text(updated, encoding="utf-8")
        print(f"updated {SHELL_SCRIPT} from {TRUST_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
