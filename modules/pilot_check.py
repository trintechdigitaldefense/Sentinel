# © 2026 TrinTech Digital Defense — authorized defensive use only
"""One-shot pilot validation: doctor + baselines + detection probes."""
from __future__ import annotations

import json
from typing import Any


def run_pilot(logger=None) -> dict:
    out: dict[str, Any] = {"ok": True, "steps": []}

    # 1. Doctor
    try:
        from modules.doctor import run_doctor
        d = run_doctor(verbose=True)
        out["doctor"] = {
            "client_ready": d.get("client_ready"),
            "summary": d.get("summary"),
            "next": d.get("next"),
        }
        out["steps"].append({"step": "doctor", "ok": d.get("ok", False)})
        if not d.get("ok"):
            out["ok"] = False
    except Exception as e:
        out["steps"].append({"step": "doctor", "ok": False, "error": str(e)})
        out["ok"] = False

    # 2. Persistence baseline if missing
    try:
        from modules.persistence_hunt import baseline_path, create_baseline, check
        if not baseline_path().exists():
            create_baseline()
            out["steps"].append({"step": "persistence-baseline", "ok": True, "created": True})
        else:
            c = check()
            out["steps"].append({"step": "persistence-check", "ok": True, "events": c.get("count", 0)})
    except Exception as e:
        out["steps"].append({"step": "persistence", "ok": False, "error": str(e)})

    # 3. SUID baseline if missing
    try:
        from modules.fim_suid import build_baseline, status as su_status
        st = su_status()
        if not st.get("baseline_exists"):
            build_baseline()
            out["steps"].append({"step": "suid-baseline", "ok": True, "created": True})
        else:
            out["steps"].append({"step": "suid", "ok": True, "count": st.get("baseline_count")})
    except Exception as e:
        out["steps"].append({"step": "suid", "ok": False, "error": str(e)})

    # 4. Behavioral probe (should return list, not crash)
    try:
        from modules.behavioral_shell import scan
        hits = scan()
        out["steps"].append({"step": "behavioral", "ok": True, "hits": len(hits)})
    except Exception as e:
        out["steps"].append({"step": "behavioral", "ok": False, "error": str(e)})
        out["ok"] = False

    # 5. Firewall dry-run
    try:
        from modules.firewall import block_ip, status as fw_status
        st = fw_status()
        r = block_ip("203.0.113.50", confirm=False)
        out["steps"].append({
            "step": "firewall-dry-run",
            "ok": bool(r.get("ok")),
            "lockout_guard": st.get("lockout_guard"),
            "backend": st.get("backend"),
        })
    except Exception as e:
        out["steps"].append({"step": "firewall", "ok": False, "error": str(e)})

    print()
    print("=" * 56)
    print("  SENTINEL PILOT CHECK")
    print("=" * 56)
    for s in out["steps"]:
        mark = "+" if s.get("ok") else "X"
        extra = {k: v for k, v in s.items() if k not in ("step", "ok")}
        print(f"  [{mark}] {s.get('step')}: {json.dumps(extra) if extra else 'ok'}")
    print("-" * 56)
    print(f"  Verdict: {'PILOT-READY' if out['ok'] else 'FIX FAILURES ABOVE'}")
    print("=" * 56)
    print()
    return out
