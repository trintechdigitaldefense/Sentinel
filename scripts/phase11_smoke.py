#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 11 smoke — correlation, AI offline summary, gated response plan."""
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
        os.environ["SENTINEL_DIR"] = tempfile.mkdtemp(prefix="sentinel-p11-")
        print(f"[*] SENTINEL_DIR={os.environ['SENTINEL_DIR']}")

    err = []
    try:
        from modules.correlation import correlate, promote_bundle_to_case
        from modules.ai_assist import offline_summary, summarize_case
        from modules.gated_response import execute_recommendation, plan_for_case_id
        from modules import cases

        alerts = [
            {
                "source": "sentinel_local",
                "host": "pc-01",
                "title": "canary touch",
                "severity": "HIGH",
                "observed_at": "2026-10-24T12:00:00+00:00",
            },
            {
                "source": "wazuh",
                "host": "pc-01",
                "title": "auth failure burst",
                "severity": "MEDIUM",
                "observed_at": "2026-10-24T12:05:00+00:00",
            },
        ]
        bundles = correlate(alerts, window_minutes=30, min_sources=2)
        print("[+] bundles", len(bundles), bundles[0]["id"] if bundles else None)
        if not bundles:
            err.append("no bundles")
        cases.init_db()
        pr = promote_bundle_to_case(bundles[0])
        cid = pr["case"]["id"]
        print("[+] case", cid)
        print("[+] offline", offline_summary(pr["case"])[:120])
        sm = summarize_case(cid)
        print("[+] summarize mode", sm.get("mode"))
        plan = plan_for_case_id(cid)
        print("[+] plan", plan.get("recommendations"))
        denied = execute_recommendation("block_ip", "1.2.3.4", confirm=False)
        if denied.get("ok"):
            err.append("execute without confirm should fail")
        print("[+] deny without confirm", denied.get("error"))
    except Exception as e:
        err.append(str(e))

    if err:
        print("[!] FAIL", err)
        return 1
    print("[+] Phase 11 smoke PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
