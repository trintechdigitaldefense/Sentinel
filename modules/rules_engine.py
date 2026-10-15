#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""FEATURE 13 — Portable rules engine (JSON/YAML)."""
from __future__ import annotations
import json
import os
import re
from pathlib import Path

def _rules_dir() -> Path:
    d = Path(__file__).resolve().parent.parent / "rules"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _data_rules() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data" / "rules"
    d.mkdir(parents=True, exist_ok=True)
    return d

DEFAULT_RULES = [
    {"id": "rs_bash_i", "name": "Interactive bash reverse shell",
     "condition": {"field": "command", "regex": r"bash\\s+-i"},
     "severity": "CRITICAL", "attack": ["T1059"], "suppression_key": "reverse_shell"},
    {"id": "rs_dev_tcp", "name": "Bash /dev/tcp",
     "condition": {"field": "command", "regex": r"/dev/tcp/"},
     "severity": "CRITICAL", "attack": ["T1059", "T1071"], "suppression_key": "reverse_shell"},
    {"id": "canary_touch", "name": "Canary file accessed",
     "condition": {"field": "reason", "equals": "canary"},
     "severity": "HIGH", "attack": ["T1005", "T1552"], "suppression_key": "canary"},
    {"id": "honey_login", "name": "Honey credential use",
     "condition": {"field": "reason", "equals": "honey_auth"},
     "severity": "CRITICAL", "attack": ["T1078", "T1110"], "suppression_key": "honey_auth"},
]

def ensure_default_rules() -> Path:
    rd = _rules_dir()
    path = rd / "default.json"
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_RULES, indent=2))
    return path

def load_rules() -> list:
    rules = []
    ensure_default_rules()
    for folder in (_rules_dir(), _data_rules()):
        for p in sorted(folder.glob("*.json")):
            try:
                data = json.loads(p.read_text())
                if isinstance(data, list):
                    rules.extend(data)
                elif isinstance(data, dict) and "rules" in data:
                    rules.extend(data["rules"])
                elif isinstance(data, dict) and "id" in data:
                    rules.append(data)
            except Exception:
                continue
        for p in list(folder.glob("*.yaml")) + list(folder.glob("*.yml")):
            try:
                import yaml
                data = yaml.safe_load(p.read_text())
                if isinstance(data, list):
                    rules.extend(data)
                elif isinstance(data, dict) and "rules" in data:
                    rules.extend(data["rules"])
            except Exception:
                continue
    return rules

def _match(cond: dict, event: dict) -> bool:
    if not cond:
        return False
    field = cond.get("field") or "detail"
    val = str(event.get(field) or event.get("command") or event.get("detail") or event.get("reason") or "")
    if "equals" in cond:
        return val.lower() == str(cond["equals"]).lower()
    if "contains" in cond:
        return str(cond["contains"]).lower() in val.lower()
    if "regex" in cond:
        try:
            return bool(re.search(cond["regex"], val, re.I))
        except re.error:
            return False
    return False

def evaluate(event: dict, rules: list = None) -> list:
    rules = rules if rules is not None else load_rules()
    hits = []
    for r in rules:
        try:
            if _match(r.get("condition") or {}, event):
                hits.append(r)
        except Exception:
            continue
    return hits

def check_events(events: list) -> dict:
    rules = load_rules()
    matched = []
    for ev in events or []:
        hits = evaluate(ev, rules)
        if hits:
            matched.append({"event": ev, "rules": hits})
    return {"ok": True, "rules_loaded": len(rules), "matches": matched, "match_count": len(matched)}
