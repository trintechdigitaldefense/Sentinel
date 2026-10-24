# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Gated response recommendations (Phase 11).

NOT full autonomous response. Default: recommend only.
Execute only when config.response.enabled and policy allows the action,
and caller passes confirm=True.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _response_cfg() -> dict:
    p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text()).get("response") or {}
        except Exception:
            pass
    return {}


def recommend_for_case(case: dict) -> list[dict]:
    """Return defensive recommendations — never executes."""
    title = (case.get("title") or "").lower()
    summary = (case.get("summary") or "").lower()
    blob = title + " " + summary
    recs = []
    if any(x in blob for x in ("ransomware", "encrypt", "canary")):
        recs.append(
            {
                "action": "isolate_hint",
                "detail": "Consider isolating the host from the network and preserving evidence.",
                "auto_safe": False,
            }
        )
    if any(x in blob for x in ("bruteforce", "auth", "ssh", "rdp", "failed login")):
        recs.append(
            {
                "action": "block_ip",
                "detail": "If a source IP is known, optional block_ip under response policy.",
                "auto_safe": False,
            }
        )
    if any(x in blob for x in ("usb", "removable")):
        recs.append(
            {
                "action": "investigate_usb",
                "detail": "Review USB watch logs; do not auto-disable devices without operator approval.",
                "auto_safe": True,
            }
        )
    if not recs:
        recs.append(
            {
                "action": "triage",
                "detail": "Continue triage: assign owner, attach alerts, export evidence if needed.",
                "auto_safe": True,
            }
        )
    return recs


def execute_recommendation(action: str, target: str = "", confirm: bool = False) -> dict:
    """Execute only with confirm=True and config.response.enabled for that action."""
    if not confirm:
        return {"ok": False, "error": "confirm=True required — autonomous execute denied"}
    cfg = _response_cfg()
    if not cfg.get("enabled"):
        return {"ok": False, "error": "response.enabled is false"}
    from modules import response_actions

    if action == "block_ip":
        return response_actions.block_ip(target, cfg)
    if action == "kill_process":
        try:
            return response_actions.kill_process(int(target), cfg)
        except Exception as e:
            return {"ok": False, "error": str(e)}
    if action in ("triage", "isolate_hint", "investigate_usb"):
        return {"ok": True, "action": action, "detail": "advisory only — no host change"}
    return {"ok": False, "error": f"unsupported or denied action: {action}"}


def plan_for_case_id(case_id: str) -> dict:
    from modules import cases

    c = cases.get_case(case_id)
    if not c:
        return {"ok": False, "error": "case not found"}
    recs = recommend_for_case(c)
    return {"ok": True, "case_id": case_id, "recommendations": recs, "execute_default": False}
