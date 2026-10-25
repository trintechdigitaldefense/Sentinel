#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Quick dry-run smoke for host firewall control plane (no root required)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.firewall import (
    VERSION,
    block_ip,
    detect_operator_ips,
    doctor,
    list_profiles,
    status,
)


def main() -> int:
    print(f"firewall VERSION={VERSION}")
    st = status()
    print("status:", json.dumps({k: st.get(k) for k in ("ok", "backend", "lockout_guard", "ipv6", "operator_ips")}, indent=2))
    assert st.get("lockout_guard") is True
    r = block_ip("203.0.113.99", confirm=False)
    assert r.get("dry_run") is True and r.get("ok") is True
    print("block dry-run:", r.get("would"))
    r2 = block_ip("127.0.0.1", confirm=True)
    assert r2.get("ok") is False
    print("localhost refused:", r2.get("error"))
    print("profiles:", list(list_profiles().get("profiles") or {}))
    print("operator_ips:", detect_operator_ips())
    print("doctor:", json.dumps(doctor(), indent=2)[:400])
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
