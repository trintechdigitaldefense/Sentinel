# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Connector contract and normalized alert schema (Phase 6).

Every connector implements:
  health_check()  -> ConnectorHealth
  fetch_events(cursor, since, limit) -> (list[NormalizedAlert], next_cursor)
  normalize(raw)  -> NormalizedAlert | None

Read-only. No blocking, isolation, or account actions from connectors.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_raw(cls, value: Any) -> "Severity":
        if value is None:
            return cls.INFORMATIONAL
        s = str(value).strip().lower()
        mapping = {
            "info": cls.INFORMATIONAL,
            "informational": cls.INFORMATIONAL,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "1": cls.INFORMATIONAL,
            "2": cls.LOW,
            "3": cls.MEDIUM,
            "4": cls.HIGH,
            "5": cls.CRITICAL,
            "0": cls.INFORMATIONAL,
            "6": cls.LOW,
            "7": cls.MEDIUM,
            "8": cls.HIGH,
            "9": cls.HIGH,
            "10": cls.CRITICAL,
            "11": cls.CRITICAL,
            "12": cls.CRITICAL,
            "13": cls.CRITICAL,
            "14": cls.CRITICAL,
            "15": cls.CRITICAL,
        }
        return mapping.get(s, cls.INFORMATIONAL)


@dataclass
class NormalizedAlert:
    """Common schema for all connectors."""

    id: str
    source: str
    source_event_id: str
    severity: Severity
    title: str
    occurred_at: str  # ISO-8601
    received_at: str  # ISO-8601
    status: str = "new"
    asset_id: str = ""
    rule_id: str = ""
    detail: str = ""
    evidence_reference: str = ""
    raw_ref: str = ""  # optional pointer; do not store large raw payloads by default
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        return d


@dataclass
class ConnectorHealth:
    name: str
    ok: bool
    last_success: Optional[str] = None
    message: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Connector(ABC):
    """Read-only connector interface."""

    name: str = "base"

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    @abstractmethod
    def health_check(self) -> ConnectorHealth:
        """Report connector health and last successful poll if known."""

    @abstractmethod
    def fetch_events(
        self,
        cursor: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> tuple[list[NormalizedAlert], Optional[str]]:
        """Retrieve authorized events only.

        Returns (alerts, next_cursor). next_cursor is None when exhausted.
        """

    @abstractmethod
    def normalize(self, raw_event: dict) -> Optional[NormalizedAlert]:
        """Map a raw source event into the internal schema. Return None to skip."""

    def acknowledge(self, cursor: str) -> None:
        """Optional: persist progress after durable processing. Default no-op."""
        return None
