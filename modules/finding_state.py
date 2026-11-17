# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Persistent notification deduplication for unchanged active findings.

This state is separate from trusted detection baselines. It tracks which
active differences have already been reported; it never approves or rewrites
a baseline.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Mapping


def _state_path(namespace: str) -> Path:
    if not re.fullmatch(r"[a-z0-9_-]{1,40}", namespace):
        raise ValueError("invalid finding-state namespace")
    data_dir = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / f"finding_state_{namespace}.json"


def newly_active(namespace: str, findings: Mapping[str, str]) -> set[str]:
    """Return keys that are new or changed since the previous check.

    Omitted findings are resolved and cleared, so a later recurrence alerts
    again. Persistence failures fail open and report all active findings.
    """
    path = _state_path(namespace)
    current = {str(key): str(value) for key, value in findings.items()}

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("version") != 1 or not isinstance(document.get("findings"), dict):
            raise ValueError("unsupported finding-state format")
        previous = document["findings"]
    except FileNotFoundError:
        previous = {}
    except Exception as exc:
        logging.getLogger("sentinel").warning(
            "Finding state unavailable for %s; reporting active findings: %s",
            namespace, exc,
        )
        previous = {}

    report = {
        key for key, fingerprint in current.items()
        if previous.get(key) != fingerprint
    }
    document = {"version": 1, "findings": current}

    fd = None
    temp_path = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        temp_path = Path(temp_name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            json.dump(document, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    except Exception as exc:
        logging.getLogger("sentinel").warning(
            "Could not persist finding state for %s; reporting active findings: %s",
            namespace, exc,
        )
        report = set(current)
    finally:
        if fd is not None:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
    return report
