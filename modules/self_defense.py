"""Self-integrity and tamper protection (feature 13)."""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.selfdef")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _baseline() -> Path:
    return _home() / "data" / "self_hashes.json"


def hash_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def core_files(repo_root: Path) -> list:
    files = [repo_root / "sentinel.py", repo_root / "setup.py"]
    mod = repo_root / "modules"
    if mod.exists():
        for p in sorted(mod.glob("*.py")):
            if p.name != "__init__.py":
                files.append(p)
    return [p for p in files if p.exists()]


def create_baseline(repo_root: Path) -> dict:
    data = {str(p.resolve()): hash_file(p) for p in core_files(repo_root)}
    path = _baseline()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"files": data}, indent=2))
    return {"ok": True, "count": len(data), "path": str(path)}


def verify(repo_root: Path) -> dict:
    path = _baseline()
    if not path.exists():
        return create_baseline(repo_root) | {"created": True}
    try:
        base = json.loads(path.read_text()).get("files") or {}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    changed = []
    for p in core_files(repo_root):
        key = str(p.resolve())
        cur = hash_file(p)
        old = base.get(key)
        if old and old != cur:
            changed.append(key)
    if changed:
        log.critical("SELF-DEFENSE: core file changes detected: %s", changed)
        return {"ok": False, "changed": changed, "severity": "CRITICAL"}
    return {"ok": True, "checked": len(base)}
