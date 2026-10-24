# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Policy-gated automatic response (Phase 12 foundation).

IMPORTANT: This is NOT silent autonomous response.
- Defaults OFF (response.auto_enabled must be true)
- Kill-switch file ~/.sentinel/data/RESPONSE_KILL_SWITCH stops all auto actions
- Every attempt is audited to response_audit.jsonl and optionally a case note
- Only allowlisted actions; rate-limited
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text()).get("response") or {}
        except Exception:
            pass
    return {}


def kill_switch_engaged() -> bool:
    return (_home() / "data" / "RESPONSE_KILL_SWITCH").exists()


def engage_kill_switch(reason: str = "operator") -> dict:
    p = _home() / "data" / "RESPONSE_KILL_SWITCH"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"engaged_at": time.time(), "reason": reason}))
    return {"ok": True, "kill_switch": True, "path": str(p)}


def clear_kill_switch() -> dict:
    p = _home() / "data" / "RESPONSE_KILL_SWITCH"
    if p.exists():
        p.unlink()
    return {"ok": True, "kill_switch": False}


def _rate_ok(cfg: dict) -> bool:
    limit = int(cfg.get("auto_max_per_hour") or 5)
    path = _home() / "data" / "auto_response_rate.json"
    now = time.time()
    try:
        data = json.loads(path.read_text()) if path.exists() else {"events": []}
    except Exception:
        data = {"events": []}
    events = [t for t in data.get("events") or [] if now - float(t) < 3600]
    if len(events) >= limit:
        return False
    events.append(now)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"events": events}))
    return True


def evaluate_case(case: dict) -> dict:
    """Decide whether auto-response would fire — does not execute."""
    cfg = _cfg()
    if not cfg.get("enabled"):
        return {"would_act": False, "reason": "response.enabled=false"}
    if not cfg.get("auto_enabled"):
        return {"would_act": False, "reason": "response.auto_enabled=false (default)"}
    if kill_switch_engaged():
        return {"would_act": False, "reason": "kill switch engaged"}
    sev = str(case.get("severity") or "").lower()
    min_sev = str(cfg.get("auto_min_severity") or "critical").lower()
    order = ["informational", "low", "medium", "high", "critical"]
    try:
        if order.index(sev) < order.index(min_sev if min_sev in order else "critical"):
            return {"would_act": False, "reason": f"severity {sev} below {min_sev}"}
    except ValueError:
        return {"would_act": False, "reason": "unknown severity"}
    allowed = cfg.get("auto_actions") or ["annotate"]
    return {"would_act": True, "actions": allowed, "reason": "policy match", "silent": False}


def maybe_auto_respond(case_id: str, actor: str = "auto_response") -> dict:
    """Execute policy-matched auto response with mandatory audit. Never silent."""
    from modules import cases
    from modules.gated_response import recommend_for_case

    cfg = _cfg()
    c = cases.get_case(case_id)
    if not c:
        return {"ok": False, "error": "case not found"}
    decision = evaluate_case(c)
    decision["case_id"] = case_id
    decision["silent"] = False
    if not decision.get("would_act"):
        return {"ok": True, "acted": False, **decision}
    if not _rate_ok(cfg):
        return {"ok": True, "acted": False, "reason": "rate limit", "case_id": case_id, "silent": False}

    results = []
    for action in decision.get("actions") or []:
        if action == "annotate":
            note = (
                f"[auto_response] Policy matched severity={c.get('severity')}. "
                f"Recommendations: {recommend_for_case(c)}. "
                f"No host mutation unless auto_actions includes block_ip/kill_process "
                f"and response flags allow it."
            )
            cases.add_note(case_id, note, author=actor)
            results.append({"action": "annotate", "ok": True})
        elif action == "block_ip" and cfg.get("block_ip") and cfg.get("auto_block_ip"):
            results.append({"action": "block_ip", "ok": False, "error": "no target IP in case — skipped"})
        else:
            results.append({"action": action, "ok": False, "error": "not permitted or advisory-only"})

    audit_path = _home() / "data" / "response_audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "ts": time.time(),
        "kind": "auto_response",
        "case_id": case_id,
        "decision": decision,
        "results": results,
        "silent": False,
        "actor": actor,
    }
    with open(audit_path, "a") as f:
        f.write(json.dumps(rec) + "\n")

    return {"ok": True, "acted": True, "case_id": case_id, "results": results, "silent": False, **decision}
