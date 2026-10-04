# Sentinel extension modules — TrinTech Digital Defense
from .phase1 import (
    quiet_should_emit,
    auto_quarantine,
    embed_canary_beacon,
    handle_canary_beacon,
    client_onboard,
    phase1_self_check,
    tls_agent_headers,
    CRITICAL_ALERTS,
)

__all__ = [
    "quiet_should_emit",
    "auto_quarantine",
    "embed_canary_beacon",
    "handle_canary_beacon",
    "client_onboard",
    "phase1_self_check",
    "tls_agent_headers",
    "CRITICAL_ALERTS",
]
