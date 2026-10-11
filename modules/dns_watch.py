#!/usr/bin/env python3
"""FEATURE 07 — DNS exfiltration heuristic."""
from __future__ import annotations
import json
import math
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

def _cfg() -> dict:
    p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def score_label(label: str) -> float:
    lab = re.sub(r"[^a-zA-Z0-9-]", "", label)
    if len(lab) < 8:
        return 0.0
    return entropy(lab.lower()) + (0.05 * max(0, len(lab) - 20))

def _read_candidates() -> list:
    paths = ["/var/log/syslog", "/var/log/messages", "/var/log/pihole.log",
             str(Path.home() / ".sentinel/data/dns_sample.log")]
    lines = []
    for p in paths:
        fp = Path(p)
        if fp.exists():
            try:
                lines.extend(fp.read_text(errors="ignore").splitlines()[-300:])
            except Exception:
                pass
    return lines

def check() -> dict:
    cfg = (_cfg().get("detection") or {})
    thr = float(cfg.get("dns_entropy_threshold") or 3.8)
    min_len = int(cfg.get("dns_min_label_len") or 25)
    events = []
    qre = re.compile(r"\b([a-zA-Z0-9-]{8,}\.[a-zA-Z0-9.-]{3,})\b")
    seen = set()
    for line in _read_candidates():
        if "NXDOMAIN" in line or " query" in line.lower() or "DNS" in line:
            for m in qre.findall(line):
                host = m.lower()
                label = host.split(".")[0]
                sc = score_label(label)
                if sc >= thr or len(label) >= min_len:
                    key = host[:80]
                    if key in seen:
                        continue
                    seen.add(key)
                    events.append({
                        "type": "dns_exfil",
                        "reason": "dns_exfil",
                        "severity": "MEDIUM",
                        "host": host,
                        "label": label,
                        "score": round(sc, 2),
                        "detail": line.strip()[:160],
                        "ts": datetime.now().isoformat(),
                    })
    return {"ok": True, "threshold": thr, "count": len(events), "events": events[:30]}
