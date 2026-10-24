# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Reference connector: Sentinel's own local alerts.log (Phase 6).

Read-only. Used as the canonical example of normalize + fetch_events.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from modules.connectors.base import (
    Connector,
    ConnectorHealth,
    NormalizedAlert,
    Severity,
    utc_now_iso,
)


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _alerts_path() -> Path:
    return _home() / "data" / "alerts.log"


class SentinelLocalConnector(Connector):
    name = "sentinel_local"

    def health_check(self) -> ConnectorHealth:
        p = _alerts_path()
        if not p.exists():
            return ConnectorHealth(
                name=self.name,
                ok=True,
                message="alerts.log not present yet (empty is healthy)",
                detail={"path": str(p)},
            )
        try:
            size = p.stat().st_size
            return ConnectorHealth(
                name=self.name,
                ok=True,
                last_success=utc_now_iso(),
                message="ok",
                detail={"path": str(p), "bytes": size},
            )
        except Exception as e:
            return ConnectorHealth(name=self.name, ok=False, message=str(e))

    def normalize(self, raw_event: dict) -> Optional[NormalizedAlert]:
        if not isinstance(raw_event, dict):
            return None
        title = (raw_event.get("title") or "").strip()
        if not title:
            return None
        fp = raw_event.get("fp") or raw_event.get("ts") or title
        ts = raw_event.get("ts") or utc_now_iso()
        sev = Severity.from_raw(raw_event.get("severity"))
        return NormalizedAlert(
            id=f"sentinel-{fp}",
            source=self.name,
            source_event_id=str(fp),
            severity=sev,
            title=title[:300],
            occurred_at=ts,
            received_at=utc_now_iso(),
            status="new",
            detail=(raw_event.get("detail") or "")[:1000],
            asset_id=str((raw_event.get("meta") or {}).get("host") or ""),
            rule_id=str((raw_event.get("meta") or {}).get("rule_id") or ""),
            extra={"meta": raw_event.get("meta") or {}},
        )

    def fetch_events(
        self,
        cursor: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> tuple[list[NormalizedAlert], Optional[str]]:
        limit = max(1, min(int(limit or 100), 500))
        p = _alerts_path()
        if not p.exists():
            return [], None

        # cursor is an integer line offset (0-based)
        start = 0
        if cursor is not None:
            try:
                start = max(0, int(cursor))
            except ValueError:
                start = 0

        lines = p.read_text(errors="ignore").splitlines()
        alerts: list[NormalizedAlert] = []
        idx = start
        while idx < len(lines) and len(alerts) < limit:
            line = lines[idx].strip()
            idx += 1
            if not line:
                continue
            try:
                raw = json.loads(line)
            except Exception:
                raw = {"title": line, "severity": "INFO", "ts": ""}
            if since and raw.get("ts") and str(raw["ts"]) < since:
                continue
            n = self.normalize(raw)
            if n:
                alerts.append(n)

        next_cursor = str(idx) if idx < len(lines) else None
        return alerts, next_cursor
