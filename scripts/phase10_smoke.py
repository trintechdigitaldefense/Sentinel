#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 10 smoke — digest job, connector local, cron line."""
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
        os.environ["SENTINEL_DIR"] = tempfile.mkdtemp(prefix="sentinel-p10-")
        print(f"[*] SENTINEL_DIR={os.environ['SENTINEL_DIR']}")

    err = []
    try:
        from modules import cases
        from modules.digest_cron import run_digest_job, crontab_line
        from modules.connector_enable import enable_local, health, fetch_and_maybe_case

        cases.init_db()
        cases.create_case(title="Phase10 open", severity="high", source="p10")
        r = run_digest_job(via="none")
        if not r.get("saved"):
            err.append("digest not saved")
        else:
            print("[+] digest saved", r["saved"])
        line = crontab_line(hour=8, minute=15)
        print("[+] crontab line:", line[:80], "...")
        print("[+]", enable_local(auto_case=True))
        print("[+] health", health("sentinel_local"))
        fr = fetch_and_maybe_case("sentinel_local", limit=5, auto_case=True)
        print("[+] fetch", fr.get("ok"), "count", fr.get("count"), "opened", fr.get("cases_opened"))
        if not fr.get("ok"):
            err.append(str(fr))
    except Exception as e:
        err.append(str(e))

    if err:
        print("[!] FAIL", err)
        return 1
    print("[+] Phase 10 smoke PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
