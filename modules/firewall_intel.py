# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Firewall intelligence — recommend / apply blocks from Sentinel alert history.

Reads alerts.log for aggressive sources (SSH failures already handled by
brute_force). Correlates repeated hostile signals into block recommendations.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _alerts_path() -> Path:
    return _home() / "data" / "alerts.log"


_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

HOSTILE_TYPES = {
    "IP_BLOCKED", "REVERSE_SHELL", "BEHAVIORAL_REVERSE_SHELL",
    "CANARY_TRIGGERED", "SIM_CANARY_TOUCH", "AUTH_FAILURE",
    "OUTBOUND_SUSPICIOUS_PORT", "NEW_SUID", "LD_PRELOAD_CREATED",
}


def analyze(limit: int = 500) -> dict:
    """Score source IPs appearing in hostile alerts."""
    path = _alerts_path()
    scores: Counter = Counter()
    samples: dict[str, list] = {}
    if not path.exists():
        return {"ok": True, "recommendations": [], "scored": {}, "note": "no alerts yet"}

    lines = path.read_text(errors="ignore").splitlines()[-limit:]
    for line in lines:
        try:
            rec = json.loads(line)
        except Exception:
            # plain text lines
            if not any(h.lower() in line.lower() for h in ("block", "fail", "shell", "canary")):
                continue
            for ip in _IP.findall(line):
                scores[ip] += 1
            continue
        at = str(rec.get("title") or rec.get("type") or rec.get("severity") or "")
        detail = str(rec.get("detail") or "") + " " + json.dumps(rec.get("meta") or {})
        hostile = any(h in at.upper() for h in HOSTILE_TYPES) or any(
            h.lower() in (at + detail).lower() for h in ("brute", "reverse", "canary", "blocked")
        )
        if not hostile:
            continue
        for ip in _IP.findall(detail + " " + at):
            if ip.startswith("127.") or ip.startswith("0."):
                continue
            scores[ip] += 2
            samples.setdefault(ip, []).append(at[:80])

    recommendations = []
    for ip, score in scores.most_common(30):
        if score < 2:
            continue
        recommendations.append({
            "ip": ip,
            "score": score,
            "samples": (samples.get(ip) or [])[:3],
            "action": "block" if score >= 4 else "watch",
        })
    return {
        "ok": True,
        "scored": dict(scores.most_common(30)),
        "recommendations": recommendations,
    }


def apply_recommendations(confirm: bool = False, min_score: int = 4) -> dict:
    """Apply firewall blocks for high-score IPs (lockout guard still applies)."""
    analysis = analyze()
    to_block = [r for r in analysis.get("recommendations") or [] if r.get("score", 0) >= min_score]
    if not confirm:
        return {
            "ok": True,
            "dry_run": True,
            "would_block": to_block,
            "hint": "pass --confirm to apply",
        }
    results = []
    try:
        from modules.firewall import block_ip
    except Exception as e:
        return {"ok": False, "error": str(e)}
    for rec in to_block:
        r = block_ip(
            rec["ip"],
            confirm=True,
            reason=f"firewall_intel score={rec['score']}",
            source="firewall_intel",
        )
        results.append({"ip": rec["ip"], "result": r})
    return {"ok": True, "applied": len(results), "results": results, "analysis": analysis}
