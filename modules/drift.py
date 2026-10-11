#!/usr/bin/env python3
"""FEATURE 01 — Baseline Drift Score with 90-day trend."""
from __future__ import annotations
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

HISTORY_DAYS = 90
MAX_POINTS = 180

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def history_path() -> Path:
    return _data() / "drift_history.json"

def _load_history() -> list:
    p = history_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else data.get("points", [])
    except Exception:
        return []

def _save_history(points: list) -> None:
    cutoff = datetime.now() - timedelta(days=HISTORY_DAYS)
    cleaned = []
    for pt in points:
        try:
            ts = datetime.fromisoformat(str(pt.get("timestamp", "")).replace("Z", ""))
            if ts >= cutoff:
                cleaned.append(pt)
        except Exception:
            continue
    if len(cleaned) > MAX_POINTS:
        cleaned = cleaned[-MAX_POINTS:]
    history_path().write_text(json.dumps(cleaned, indent=2))

def _find_baseline() -> Optional[Path]:
    candidates = [
        _data() / "integrity_baseline" / "integrity_baseline.json",
        _data() / "integrity_baseline.json",
    ]
    for p in candidates:
        if p.exists() and p.stat().st_size > 10:
            return p
    return None

def _count_baseline_entries(baseline: dict) -> int:
    if not baseline:
        return 0
    if isinstance(baseline, list):
        return len(baseline)
    for key in ("files", "entries", "paths", "baseline"):
        if isinstance(baseline.get(key), dict):
            return len(baseline[key])
        if isinstance(baseline.get(key), list):
            return len(baseline[key])
    if all(isinstance(v, (str, dict)) for v in list(baseline.values())[:5]):
        return len(baseline)
    return max(len(baseline), 1)

def compute_score(changed_paths: Optional[list] = None, total_files: Optional[int] = None) -> dict:
    changed_paths = list(changed_paths or [])
    bl_path = _find_baseline()
    if total_files is None:
        total_files = 0
        if bl_path:
            try:
                total_files = _count_baseline_entries(json.loads(bl_path.read_text()))
            except Exception:
                total_files = 0
    if total_files is None or total_files <= 0:
        score = 0.0
        note = "no_baseline" if not bl_path else "empty_baseline"
    else:
        n_changed = len(changed_paths)
        n_changed = min(n_changed, total_files)
        score = round(100.0 * (1.0 - (n_changed / float(total_files))), 2)
        note = "ok" if bl_path else "scored_without_file"
    point = {
        "timestamp": datetime.now().isoformat(),
        "score": score,
        "total_files": total_files,
        "changed_count": len(changed_paths),
        "changed_paths": changed_paths[:50],
        "note": note,
    }
    hist = _load_history()
    hist.append(point)
    _save_history(hist)
    return point

def record_from_integrity_result(result: Any = None) -> dict:
    changed = []
    total = None
    if isinstance(result, dict):
        for key in ("changed", "changed_paths", "modifications", "failed"):
            val = result.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        changed.append(item)
                    elif isinstance(item, dict):
                        changed.append(str(item.get("path") or item.get("file") or item))
        total = result.get("total") or result.get("total_files") or result.get("checked")
    elif isinstance(result, list):
        changed = [str(x) for x in result]
    return compute_score(changed, total)

def trend(days: int = 90) -> dict:
    hist = _load_history()
    if not hist:
        return {
            "ok": True,
            "points": 0,
            "latest_score": None,
            "oldest_score": None,
            "delta": None,
            "verdict": "No drift history yet — run integrity to start scoring.",
            "history": [],
        }
    latest = hist[-1]
    oldest = hist[0]
    delta = None
    try:
        delta = round(float(latest["score"]) - float(oldest["score"]), 2)
    except Exception:
        pass
    latest_s = latest.get("score")
    verdict = _verdict(latest_s, delta, latest.get("changed_count", 0))
    return {
        "ok": True,
        "points": len(hist),
        "latest_score": latest_s,
        "oldest_score": oldest.get("score"),
        "delta": delta,
        "verdict": verdict,
        "latest": latest,
        "history": hist[-30:],
    }

def _verdict(score, delta, changed_count) -> str:
    if score is None:
        return "No score available."
    if score >= 98 and (delta is None or delta >= -2):
        return f"Baseline healthy at {score}% intact — minimal drift."
    if score >= 90:
        return f"Your network is {score}% baseline-intact — {changed_count} change(s) since last baseline."
    if score >= 75:
        return (
            f"Your network drifted (now {score}% intact"
            + (f", {delta:+g} pts over the period" if delta is not None else "")
            + f") — driven by {changed_count} monitored change(s)."
        )
    return (
        f"Significant baseline drift: only {score}% intact "
        f"({changed_count} changes). Review integrity findings before renewal period ends."
    )

def print_report() -> dict:
    t = trend()
    print()
    print("=" * 56)
    print("  SENTINEL DRIFT REPORT (90-day)")
    print("=" * 56)
    if t["points"] == 0:
        print("  No history. Run: python3 sentinel.py integrity")
    else:
        print(f"  Points:        {t['points']}")
        print(f"  Latest score:  {t['latest_score']}% intact")
        print(f"  Oldest score:  {t['oldest_score']}%")
        print(f"  Delta:         {t['delta']}")
        print(f"  Verdict:       {t['verdict']}")
        print("-" * 56)
        print("  Recent:")
        for pt in (t.get("history") or [])[-8:]:
            ts = str(pt.get("timestamp", ""))[:19]
            print(f"    {ts}  {pt.get('score')}%  changed={pt.get('changed_count')}")
    print("=" * 56)
    print()
    return t

def sparkline() -> str:
    hist = _load_history()
    if len(hist) < 2:
        return ""
    scores = [float(p.get("score") or 0) for p in hist[-20:]]
    blocks = "▁▂▃▄▅▆▇█"
    lo, hi = min(scores), max(scores)
    span = (hi - lo) or 1.0
    out = []
    for s in scores:
        idx = int((s - lo) / span * (len(blocks) - 1))
        out.append(blocks[idx])
    return "".join(out)
