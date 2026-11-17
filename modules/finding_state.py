# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Persistent notification deduplication for unchanged active findings.

Notification state is separate from trusted detection baselines.
A finding is only marked handled after delivery, durable queueing,
or an intentional suppression has been confirmed.
"""
from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Mapping, Iterable

_LOG = logging.getLogger("sentinel")


# Serialize finding notification workflows across threads and processes.
_LOCK_GUARD = threading.RLock()
_LOCK_LOCAL = threading.local()


@contextmanager
def locked(namespace: str):
    """Hold an exclusive, re-entrant process lock for one finding namespace."""
    state_file = _state_path(namespace)
    lock_file = state_file.with_name(state_file.name + ".lock")
    key = str(lock_file)

    with _LOCK_GUARD:
        held = getattr(_LOCK_LOCAL, "held", None)
        if held is None:
            held = {}
            _LOCK_LOCAL.held = held

        # Nested state operations reuse the outer workflow lock.
        if key in held:
            held[key] += 1
            try:
                yield
            finally:
                held[key] -= 1
            return

        fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            held[key] = 1
            try:
                yield
            finally:
                held.pop(key, None)
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _state_path(namespace: str) -> Path:
    if not re.fullmatch(r"[a-z0-9_-]{1,40}", namespace):
        raise ValueError("invalid finding-state namespace")

    data_dir = (
        Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
        / "data"
    )
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / f"finding_state_{namespace}.json"


def _load(path: Path) -> dict[str, str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(document, dict)
            or document.get("version") != 1
            or not isinstance(document.get("findings"), dict)
        ):
            raise ValueError("unsupported finding-state format")

        return {
            str(key): str(value)
            for key, value in document["findings"].items()
        }
    except FileNotFoundError:
        return {}


def _save(path: Path, findings: Mapping[str, str]) -> None:
    fd = None
    temp_path = None

    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=str(path.parent),
        )
        temp_path = Path(temp_name)
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            json.dump(
                {"version": 1, "findings": dict(findings)},
                stream,
                sort_keys=True,
                indent=2,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temp_path, path)

    finally:
        if fd is not None:
            os.close(fd)

        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def pending_active(
    namespace: str,
    findings: Mapping[str, str],
) -> set[str]:
    """Return new or changed findings without marking them handled."""
    current = {
        str(key): str(value)
        for key, value in findings.items()
    }

    try:
        with locked(namespace):
            previous = _load(_state_path(namespace))
    except Exception as exc:
        _LOG.warning(
            "Finding state unavailable for %s; reporting active findings: %s",
            namespace,
            exc,
        )
        return set(current)

    return {
        key
        for key, fingerprint in current.items()
        if previous.get(key) != fingerprint
    }

def mark_handled(
    namespace: str,
    findings: Mapping[str, str],
    handled_keys: Iterable[str],
) -> None:
    """Persist handled findings and remove findings that have resolved."""
    current = {
        str(key): str(value)
        for key, value in findings.items()
    }
    handled = {str(key) for key in handled_keys}

    try:
        with locked(namespace):
            path = _state_path(namespace)
            previous = _load(path)

            updated = {
                key: fingerprint
                for key, fingerprint in current.items()
                if key in handled or previous.get(key) == fingerprint
            }

            _save(path, updated)

    except Exception as exc:
        _LOG.warning(
            "Could not persist handled finding state for %s: %s",
            namespace,
            exc,
        )

def newly_active(
    namespace: str,
    findings: Mapping[str, str],
) -> set[str]:
    """Backward-compatible API: return and immediately mark new findings."""
    current = {
        str(key): str(value)
        for key, value in findings.items()
    }

    try:
        with locked(namespace):
            report = pending_active(namespace, current)
            mark_handled(namespace, current, report)
            return report
    except Exception as exc:
        _LOG.warning(
            "Finding state unavailable for %s; reporting active findings: %s",
            namespace,
            exc,
        )
        return set(current)
