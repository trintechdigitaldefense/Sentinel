# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Alert severity scoring model (feature 6).

INFO     — routine status
LOW      — minor anomaly, informational
MEDIUM   — suspicious, worth review
HIGH     — likely malicious / policy breach
CRITICAL — active compromise indicators / Sentinel tamper
"""
from __future__ import annotations

from typing import Optional

# detection type → base severity
BASE = {
    "NEW_DEVICE": "MEDIUM",
    "REVERSE_SHELL": "CRITICAL",
    "CANARY_TRIGGERED": "HIGH",
    "DECOY_MODIFIED": "HIGH",
    "FIM_MODIFIED": "MEDIUM",
    "SELF_INTEGRITY_VIOLATION": "CRITICAL",
    "SSH_BRUTE": "HIGH",
    "SUSPICIOUS_PROCESS": "HIGH",
    "USB_INSERT": "LOW",
    "PERSISTENCE_CHANGE": "HIGH",
    "MISSING_AGENT": "HIGH",
    "OUTBOUND_RISKY": "MEDIUM",
    "HEARTBEAT": "INFO",
    "SERVICE_START": "INFO",
    "GENERIC": "LOW",
}

ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def score(detection_type: str, *, context: Optional[dict] = None) -> str:
    """Return severity string for a detection."""
    t = (detection_type or "GENERIC").upper()
    sev = BASE.get(t, "LOW")
    ctx = context or {}
    # escalate if intel says bad
    if ctx.get("intel_malicious"):
        sev = _max(sev, "HIGH")
    if ctx.get("repeated", 0) >= 5:
        sev = _max(sev, "HIGH")
    if t == "FIM_MODIFIED" and ctx.get("path", "").startswith("/etc"):
        sev = _max(sev, "HIGH")
    return sev


def _max(a: str, b: str) -> str:
    return a if ORDER.index(a) >= ORDER.index(b) else b


def list_model() -> dict:
    return {"base": BASE, "order": ORDER}
