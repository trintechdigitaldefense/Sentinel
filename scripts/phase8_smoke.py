#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 8 acceptance smoke — cases + hooks + dashboard shape.

Run from repo root:
  python3 scripts/phase8_smoke.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    if not os.environ.get("SENTINEL_DIR"):
        td = tempfile.mkdtemp(prefix="sentinel-p8-")
        os.environ["SENTINEL_DIR"] = td
        print(f"[*] SENTINEL_DIR={td} (ephemeral)")

    errors = []

    try:
        from modules import cases

        cases.init_db()
        r = cases.create_case(
            title="Phase8 smoke case",
            severity="high",
            source="phase8_smoke",
            summary="automated acceptance",
            actor="phase8_smoke",
        )
        if not r.get("ok"):
            errors.append(f"create_case failed: {r}")
        else:
            cid = r["case"]["id"]
            print(f"[+] case created {cid}")
            rows = cases.list_cases(status="new", limit=10)
            if not any(c.get("id") == cid for c in rows):
                errors.append("created case not in list_cases")
            else:
                print("[+] list_cases ok")
            ev = cases.export_evidence(cid)
            if not ev.get("ok"):
                errors.append(f"export_evidence failed: {ev}")
            else:
                print(f"[+] evidence {ev.get('path') or ev}")
    except Exception as e:
        errors.append(f"cases: {e}")

    try:
        from modules.case_hooks import maybe_open_case_from_engine_alert

        r = maybe_open_case_from_engine_alert(
            "CANARY_TRIGGERED",
            {"path": "/tmp/phase8-canary", "canary_id": "p8-smoke"},
            actor="phase8_smoke",
        )
        if not r or not r.get("ok"):
            errors.append(f"case_hooks failed: {r}")
        else:
            print(f"[+] case_hooks opened {r['case']['id']}")
        r2 = maybe_open_case_from_engine_alert(
            "CANARY_TRIGGERED",
            {"path": "/tmp/phase8-canary", "canary_id": "p8-smoke"},
            actor="phase8_smoke",
        )
        if r2 is not None:
            errors.append("case_hooks dedup failed")
        else:
            print("[+] case_hooks dedup ok")
    except Exception as e:
        errors.append(f"case_hooks: {e}")

    try:
        from modules.dashboard import collect_full

        st = collect_full()
        if "cases_open" not in st:
            errors.append("collect_full missing cases_open")
        else:
            print(
                f"[+] dashboard cases_open count={st.get('cases_open_count')} "
                f"rows={len(st.get('cases_open') or [])}"
            )
    except Exception as e:
        errors.append(f"dashboard: {e}")

    try:
        from modules.connectors import get_connector

        conn = get_connector("sentinel_local", {})
        h = conn.health_check()
        alerts, _ = conn.fetch_events(limit=5)
        print(f"[+] connector local health={h.ok} alerts={len(alerts)}")
    except Exception as e:
        errors.append(f"connector: {e}")

    if errors:
        print("\n[!] FAIL")
        for e in errors:
            print("   -", e)
        return 1
    print("\n[+] Phase 8 smoke PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
