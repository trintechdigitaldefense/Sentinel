# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Optional AI-assisted case notes (Phase 11).

Default: offline template summary (no network).
Optional: OpenAI-compatible HTTP API if config.ai.enabled and api_key set.
Never auto-executes response actions.
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Optional


def _cfg() -> dict:
    p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text()).get("ai") or {}
        except Exception:
            pass
    return {}


def offline_summary(case: dict) -> str:
    lines = [
        f"Case {case.get('id')}: {case.get('title')}",
        f"Status: {case.get('status')} · Severity: {case.get('severity')}",
        f"Source: {case.get('source') or 'n/a'} · Assignee: {case.get('assignee') or 'unassigned'}",
    ]
    if case.get("summary"):
        lines.append(f"Summary: {case['summary'][:500]}")
    notes = case.get("notes") or []
    if notes:
        lines.append(f"Notes: {len(notes)} (latest: {(notes[-1].get('body') or '')[:120]})")
    lines.append(
        "Suggested next steps: verify host integrity, review related alerts, "
        "export evidence if client-facing, close as false_positive only after confirmation."
    )
    return "\n".join(lines)


def llm_summary(case: dict, cfg: Optional[dict] = None) -> dict:
    """Call OpenAI-compatible chat completions if configured."""
    cfg = cfg if cfg is not None else _cfg()
    if not cfg.get("enabled") or not cfg.get("api_key"):
        return {"ok": True, "mode": "offline", "text": offline_summary(case)}
    base = (cfg.get("base_url") or "https://api.openai.com/v1").rstrip("/")
    model = cfg.get("model") or "gpt-4o-mini"
    prompt = (
        "You are a defensive SOC assistant for an MSP in Trinidad & Tobago. "
        "Summarize this security case in plain language for an operator. "
        "Do not invent IOCs. Suggest only defensive next steps.\n\n"
        + json.dumps(
            {k: case.get(k) for k in ("id", "title", "status", "severity", "source", "summary", "notes")},
            default=str,
        )[:4000]
    )
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 400,
        }
    ).encode()
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg['api_key']}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode())
            text = data["choices"][0]["message"]["content"]
            return {"ok": True, "mode": "llm", "text": text, "model": model}
    except Exception as e:
        return {"ok": True, "mode": "offline_fallback", "text": offline_summary(case), "error": str(e)}


def summarize_case(case_id: str) -> dict:
    from modules import cases

    c = cases.get_case(case_id)
    if not c:
        return {"ok": False, "error": "case not found"}
    r = llm_summary(c)
    if r.get("ok") and r.get("text"):
        try:
            cases.add_note(case_id, f"[ai-assist/{r.get('mode')}]\n{r['text']}", author="ai_assist")
        except Exception:
            pass
    r["case_id"] = case_id
    return r
