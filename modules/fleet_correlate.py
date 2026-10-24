# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Fleet-side correlation helper (Phase 11).

Pulls local connector alerts + optional second source, correlates,
optionally promotes high-score bundles to cases. This is **not** a
full multi-tenant cloud SIEM — it is correlation on the agent/MSP host.
"""
from __future__ import annotations

from typing import Optional

from modules.correlation import correlate_from_connectors, promote_bundle_to_case


def run(
    sources: Optional[list[str]] = None,
    window_minutes: int = 30,
    promote_min_score: int = 4,
    promote: bool = False,
) -> dict:
    result = correlate_from_connectors(sources=sources, window_minutes=window_minutes)
    promoted = []
    if promote:
        for b in result.get("bundles") or []:
            if (b.get("score") or 0) >= promote_min_score:
                r = promote_bundle_to_case(b)
                if r.get("ok"):
                    promoted.append(r["case"]["id"])
    result["promoted_cases"] = promoted
    result["promote"] = promote
    return result
