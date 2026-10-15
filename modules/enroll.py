"""Agent enrollment to central server (feature 10)."""
from __future__ import annotations

import json
import os
from pathlib import Path


def enroll(server_url: str, api_key: str) -> dict:
    home = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
    cfg_path = home / "config.json"
    cfg = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            cfg = {}
    cfg.setdefault("central", {})
    cfg["central"]["enabled"] = True
    cfg["central"]["server_url"] = server_url.rstrip("/")
    cfg["central"]["api_key"] = api_key
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2))
    return {"ok": True, "central": cfg["central"]}
