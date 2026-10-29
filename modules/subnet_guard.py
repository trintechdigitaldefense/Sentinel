# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Reject overly wide scan subnets (doctor FAIL and safe defaults)."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def is_too_wide(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except Exception:
        return True
    # IPv4: anything larger than /16 is too wide for SMB pilot defaults
    if net.version == 4 and net.prefixlen < 16:
        return True
    # IPv6: larger than /48
    if net.version == 6 and net.prefixlen < 48:
        return True
    return False


def filter_safe_subnets(subnets: list[str], fallback: str = "192.168.1.0/24") -> list[str]:
    safe = [s for s in (subnets or []) if s and not is_too_wide(s)]
    return safe or [fallback]


def sanitize_config_subnets(config_path: Path | None = None) -> dict[str, Any]:
    """Rewrite config scan_subnets if any entry is too wide. Returns summary."""
    path = config_path or (_home() / "config.json")
    if not path.exists():
        return {"ok": True, "changed": False, "reason": "no config"}
    try:
        cfg = json.loads(path.read_text())
    except Exception as e:
        return {"ok": False, "error": str(e)}
    net = cfg.setdefault("network", {})
    old = list(net.get("scan_subnets") or [])
    new = filter_safe_subnets(old)
    if new == old:
        return {"ok": True, "changed": False, "subnets": new}
    net["scan_subnets"] = new
    path.write_text(json.dumps(cfg, indent=2))
    try:
        import os as _os
        _os.chmod(path, 0o600)
    except Exception:
        pass
    return {"ok": True, "changed": True, "old": old, "subnets": new}
