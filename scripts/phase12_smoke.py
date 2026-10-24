#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 12 smoke — tenants, UEBA-lite, auto_response (never silent)."""
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
        os.environ["SENTINEL_DIR"] = tempfile.mkdtemp(prefix="sentinel-p12-")
        print(f"[*] SENTINEL_DIR={os.environ['SENTINEL_DIR']}")
    err = []
    try:
        from modules import tenants, cases
        from modules.ueba_lite import score_hosts
        from modules.auto_response import (
            evaluate_case,
            maybe_auto_respond,
            engage_kill_switch,
            clear_kill_switch,
            kill_switch_engaged,
        )

        r = tenants.create_tenant("Demo Client TT")
        assert r["ok"]
        print("[+] tenant", r["tenant"]["id"])
        assert tenants.list_tenants()
        sc = score_hosts()
        print("[+] ueba_lite hosts", len(sc.get("hosts") or []), sc.get("note"))
        cases.init_db()
        c = cases.create_case(title="critical pilot", severity="critical", source="p12")
        cid = c["case"]["id"]
        d = evaluate_case(c["case"])
        print("[+] evaluate (default off)", d)
        if d.get("would_act"):
            err.append("auto should be off by default")
        cfg_path = Path(os.environ["SENTINEL_DIR"]) / "config.json"
        cfg_path.write_text(
            json.dumps(
                {
                    "response": {
                        "enabled": True,
                        "auto_enabled": True,
                        "auto_min_severity": "critical",
                        "auto_actions": ["annotate"],
                        "auto_max_per_hour": 10,
                    }
                }
            )
        )
        ar = maybe_auto_respond(cid)
        print("[+] auto_respond", ar)
        if ar.get("silent") is not False and ar.get("silent") is not None:
            err.append("must not be silent")
        if not ar.get("acted"):
            err.append("expected annotate action")
        engage_kill_switch("smoke")
        assert kill_switch_engaged()
        ar2 = maybe_auto_respond(cid)
        print("[+] after kill switch", ar2.get("reason") or ar2)
        clear_kill_switch()
    except Exception as e:
        err.append(str(e))
    if err:
        print("[!] FAIL", err)
        return 1
    print("[+] Phase 12 smoke PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
