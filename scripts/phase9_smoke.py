#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 9 smoke — digest, client note, false_positive suppression."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    if not os.environ.get("SENTINEL_DIR"):
        os.environ["SENTINEL_DIR"] = tempfile.mkdtemp(prefix="sentinel-p9-")
        print(f"[*] SENTINEL_DIR={os.environ['SENTINEL_DIR']}")

    err = []
    try:
        from modules import cases
        from modules.msp_digest import format_digest
        from modules.client_notes import save_client_note

        cases.init_db()
        r = cases.create_case(title="Phase9 smoke", severity="high", source="p9")
        cid = r["case"]["id"]
        print("[+] case", cid)
        print(format_digest()[:400])
        note = save_client_note(cid, client_name="Smoke Client")
        print("[+] note", note.get("path"))
        st = cases.set_status(cid, "false_positive")
        print("[+] FP suppression", st.get("suppression"))
        if not st.get("suppression", {}).get("ok"):
            err.append("suppression failed")
    except Exception as e:
        err.append(str(e))

    if err:
        print("[!] FAIL", err)
        return 1
    print("[+] Phase 9 smoke PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
