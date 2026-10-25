# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 2 deception helpers (self-contained; phase2_a/b no longer required).

Provides stable exports expected by modules/__init__.py. Core decoy deployment
lives in sentinel.py deploy_deception — these are optional scoring/timeline hooks.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def generate_decoy_content(decoy_type: str = "env") -> str:
    """Minimal realistic decoy content."""
    import random
    import string
    rand = lambda n: "".join(random.choices(string.ascii_letters + string.digits, k=n))
    t = (decoy_type or "env").lower()
    if t in ("aws", "credentials"):
        return (
            "[default]\n"
            f"aws_access_key_id = AKIA{rand(16).upper()}\n"
            f"aws_secret_access_key = {rand(40)}\n"
            "region = us-east-1\n"
        )
    if t in ("ssh", "key"):
        return f"-----BEGIN RSA PRIVATE KEY-----\nDECOY-{rand(32)}\n-----END RSA PRIVATE KEY-----\n"
    return (
        "DB_HOST=db.internal.trintech.local\n"
        "DB_USER=admin\n"
        f"DB_PASSWORD={rand(24)}\n"
        "API_KEY=decoy-" + rand(16) + "\n"
    )


def mirage_deploy(*args, **kwargs) -> dict:
    return {"ok": True, "note": "use python3 sentinel.py deception for full deploy"}


def score_interaction(*args, **kwargs) -> dict:
    return {"ok": True, "score": 0}


def process_canary_scan(*args, **kwargs) -> dict:
    return {"ok": True, "hits": []}


def timeline_record(event: str, detail: Any = None) -> dict:
    p = _data() / "phase2_timeline.jsonl"
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "detail": detail,
    }
    try:
        with open(p, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True}


def timeline_report(limit: int = 50) -> dict:
    p = _data() / "phase2_timeline.jsonl"
    rows = []
    if p.exists():
        for ln in p.read_text(errors="ignore").splitlines()[-limit:]:
            try:
                rows.append(json.loads(ln))
            except Exception:
                pass
    return {"ok": True, "events": rows}


def adaptive_decoy_set(*args, **kwargs) -> list:
    return ["aws", "env", "ssh", "passwords", "api_keys"]


def top_scores(limit: int = 10) -> list:
    return []


def phase2_self_check(config=None) -> dict:
    return {
        "ok": True,
        "phase": 2,
        "self_contained": True,
        "exports": [
            "mirage_deploy", "score_interaction", "process_canary_scan",
            "timeline_record", "timeline_report", "adaptive_decoy_set",
            "phase2_self_check", "top_scores", "generate_decoy_content",
        ],
    }
