#!/usr/bin/env python3
"""FEATURE 15 — Ransomware tripwire folder."""
from __future__ import annotations
import hashlib
import json
import math
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

def _data() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def tripwire_dir() -> Path:
    p = _data() / "tripwire_canary"
    p.mkdir(parents=True, exist_ok=True)
    return p

def baseline_path() -> Path:
    return _data() / "tripwire_baseline.json"

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def deploy(n_files: int = 8) -> dict:
    d = tripwire_dir()
    files = []
    for i in range(n_files):
        name = f"INVOICE_{i+1:02d}_CONFIDENTIAL.txt"
        p = d / name
        content = f"TrinTech canary document {i+1}\nDo not encrypt — monitoring tripwire\nref={hashlib.sha1(str(i).encode()).hexdigest()[:12]}\n"
        p.write_text(content)
        files.append(str(p))
    base = {}
    for f in d.iterdir():
        if f.is_file():
            raw = f.read_bytes()
            base[f.name] = {"sha256": hashlib.sha256(raw).hexdigest(), "entropy": round(_entropy(raw), 3),
                            "size": len(raw), "suffix": f.suffix.lower()}
    baseline_path().write_text(json.dumps({"created": datetime.now().isoformat(), "files": base}, indent=2))
    return {"ok": True, "dir": str(d), "files": len(files), "path": str(baseline_path())}

def check() -> dict:
    bp = baseline_path()
    d = tripwire_dir()
    if not bp.exists():
        return {"ok": True, "needs_deploy": True, "events": [], "detail": "run tripwire-deploy first"}
    try:
        base = json.loads(bp.read_text()).get("files") or {}
    except Exception:
        return {"ok": False, "events": [], "detail": "corrupt baseline"}
    events = []
    current = {f.name: f for f in d.iterdir() if f.is_file()}
    for name in base:
        if name not in current:
            events.append({"type": "ransomware", "reason": "ransomware", "severity": "CRITICAL",
                           "detail": f"Tripwire file missing: {name}", "path": str(d / name),
                           "ts": datetime.now().isoformat()})
    renamed = entropy_jumps = 0
    for name, f in current.items():
        raw = f.read_bytes()
        ent = _entropy(raw)
        if name not in base:
            if f.suffix.lower() in (".encrypted", ".locked", ".crypto", ".crypt", ".enc"):
                renamed += 1
                events.append({"type": "ransomware", "reason": "ransomware", "severity": "CRITICAL",
                               "detail": f"Suspicious extension: {name}", "path": str(f),
                               "ts": datetime.now().isoformat()})
            continue
        old = base[name]
        if old.get("sha256") != hashlib.sha256(raw).hexdigest():
            if ent - float(old.get("entropy") or 0) > 1.5:
                entropy_jumps += 1
                events.append({"type": "ransomware", "reason": "ransomware", "severity": "CRITICAL",
                               "detail": f"Entropy jump on {name}: {old.get('entropy')} -> {round(ent,3)}",
                               "path": str(f), "ts": datetime.now().isoformat()})
            elif old.get("suffix") != f.suffix.lower():
                renamed += 1
                events.append({"type": "ransomware", "reason": "ransomware", "severity": "CRITICAL",
                               "detail": f"Extension change on {name}", "path": str(f),
                               "ts": datetime.now().isoformat()})
    if renamed >= 3 or entropy_jumps >= 3:
        events.insert(0, {"type": "ransomware", "reason": "ransomware", "severity": "CRITICAL",
                          "detail": f"MASS tripwire trigger renamed={renamed} entropy_jumps={entropy_jumps}",
                          "ts": datetime.now().isoformat()})
    return {"ok": True, "count": len(events), "events": events, "dir": str(d)}
