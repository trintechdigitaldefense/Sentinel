# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Encrypted backup / restore of Sentinel state."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _paths_to_backup() -> list:
    h = _home()
    candidates = [
        h / "config.json",
        h / "data" / "alerts.log",
        h / "data" / "alert_state.json",
        h / "data" / "alert_dedup.json",
        h / "data" / "integrity_baseline",
        h / "data" / "self_hashes.json",
        h / "data" / "cron_baseline.json",
        h / "data" / "deception_artifacts",
    ]
    return [p for p in candidates if p.exists()]


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 120000, dklen=32)


def _xor_stream(data: bytes, key: bytes) -> bytes:
    # Simple stream cipher for offline archives (stdlib only). Prefer real crypto in prod.
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


def backup(out_path: str, passphrase: str = "sentinel") -> dict:
    out = Path(out_path)
    items = _paths_to_backup()
    if not items:
        return {"ok": False, "error": "nothing to backup under ~/.sentinel"}
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        manifest = {"created": datetime.now().isoformat(), "files": []}
        tar_path = td_path / "payload.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            for p in items:
                arc = p.relative_to(_home())
                tar.add(p, arcname=str(arc))
                manifest["files"].append(str(arc))
        (td_path / "manifest.json").write_text(json.dumps(manifest, indent=2))
        raw = tar_path.read_bytes() + b"\n---MANIFEST---\n" + (td_path / "manifest.json").read_bytes()
        salt = os.urandom(16)
        key = _derive_key(passphrase, salt)
        enc = salt + _xor_stream(raw, key)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(enc)
    return {"ok": True, "path": str(out), "files": len(items), "bytes": out.stat().st_size}


def restore(archive_path: str, passphrase: str = "sentinel", force: bool = False) -> dict:
    path = Path(archive_path)
    if not path.exists():
        return {"ok": False, "error": "archive not found"}
    blob = path.read_bytes()
    if len(blob) < 20:
        return {"ok": False, "error": "archive too small"}
    salt, enc = blob[:16], blob[16:]
    key = _derive_key(passphrase, salt)
    raw = _xor_stream(enc, key)
    if b"---MANIFEST---" not in raw:
        return {"ok": False, "error": "bad passphrase or corrupt archive"}
    tar_bytes, man_bytes = raw.split(b"\n---MANIFEST---\n", 1)
    try:
        manifest = json.loads(man_bytes.decode())
    except Exception as e:
        return {"ok": False, "error": f"manifest: {e}"}
    home = _home()
    baseline = home / "data" / "integrity_baseline"
    if baseline.exists() and not force:
        # refuse if local baseline newer than archive time
        try:
            arch_ts = datetime.fromisoformat(manifest.get("created", "")[:19])
            local_ts = datetime.fromtimestamp(baseline.stat().st_mtime)
            if local_ts > arch_ts:
                return {
                    "ok": False,
                    "error": "local FIM baseline is newer than backup; pass force=True to overwrite",
                }
        except Exception:
            pass
    with tempfile.TemporaryDirectory() as td:
        tar_path = Path(td) / "payload.tar.gz"
        tar_path.write_bytes(tar_bytes)
        home.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(home, filter='data')
    return {"ok": True, "restored": manifest.get("files", []), "to": str(home)}
