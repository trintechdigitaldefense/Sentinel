# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Read-only connectors for external (and local) security telemetry.

Phase 6: connector contract + Sentinel-local reference + Wazuh skeleton.
No autonomous response from external sources.
"""
from modules.connectors.base import (
    Connector,
    NormalizedAlert,
    ConnectorHealth,
    Severity,
)
from modules.connectors.sentinel_local import SentinelLocalConnector
from modules.connectors.wazuh import WazuhConnector

__all__ = [
    "Connector",
    "NormalizedAlert",
    "ConnectorHealth",
    "Severity",
    "SentinelLocalConnector",
    "WazuhConnector",
    "get_connector",
]


def get_connector(name: str, config: dict | None = None):
    """Factory for known connectors."""
    name = (name or "").strip().lower()
    config = config or {}
    if name in ("sentinel", "sentinel_local", "local"):
        return SentinelLocalConnector(config)
    if name in ("wazuh",):
        return WazuhConnector(config)
    raise ValueError(f"Unknown connector: {name}. Known: sentinel_local, wazuh")
