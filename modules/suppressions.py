#!/usr/bin/env python3
"""FEATURE 12 — False-positive memory (learn-by-acknowledge)."""
from __future__ import annotations
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

def _path() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d / "suppressions.json"

def load() -> list:
    p = _path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else data.get("rules", [])
    except Exception:
        return []

def save(rules: list) -> None:
    _path().write_text(json.dumps(rules, indent=2))

def add_suppression(detection_type: str, pattern: str, host: Optional[str] = None, note: str = "") -> dict:
    rules = load()
    rule = {
        "id": f"sup_{len(rules)+1}_{int(datetime.now().timestamp())}",
        "detection_type": (detection_type or "*").lower(),
        "pattern": pattern,
        "host": host or "*",
        "note": note,
        "created": datetime.now().isoformat(),
    }
    rules.append(rule)
    save(rules)
    return rule

def is_suppressed(event: dict, host: Optional[str] = None) -> bool:
    rules = load()
    if not rules:
        return False
    try:
        default_host = os.uname().nodename
    except Exception:
        default_host = "host"
    host = (host or event.get("host") or default_host).lower()
    etype = str(event.get("type") or event.get("reason") or "").lower()
    hay = " ".join(str(event.get(k) or "") for k in ("detail", "path", "command", "pattern", "username", "reason", "type")).lower()
    for r in rules:
        rh = (r.get("host") or "*").lower()
        if rh not in ("*", host):
            continue
        rt = (r.get("detection_type") or "*").lower()
        if rt not in ("*", etype) and rt not in etype and etype not in rt:
            continue
        pat = r.get("pattern") or ""
        if not pat:
            continue
        try:
            if re.search(pat, hay, re.I) or pat.lower() in hay:
                return True
        except re.error:
            if pat.lower() in hay:
                return True
    return False

def filter_events(events: list, host: Optional[str] = None) -> list:
    return [e for e in (events or []) if not is_suppressed(e, host)]

def list_rules() -> list:
    return load()

def remove_rule(rule_id: str) -> bool:
    rules = load()
    new = [r for r in rules if r.get("id") != rule_id]
    if len(new) == len(rules):
        return False
    save(new)
    return True

def print_rules() -> None:
    rules = load()
    print(f"Suppressions: {len(rules)}")
    for r in rules:
        print(f"  {r.get('id')}: type={r.get('detection_type')} host={r.get('host')} pat={r.get('pattern')!r}")
