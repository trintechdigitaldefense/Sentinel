# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Dashboard role helpers: admin vs viewer."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or os.urandom(8).hex()
    dig = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 80000)
    return f"{salt}${dig.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        # plaintext legacy compare
        return hmac.compare_digest(password or "", stored or "")
    salt, dig = stored.split("$", 1)
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 80000).hex()
    return hmac.compare_digest(check, dig)


def get_role(cfg: dict) -> str:
    dash = (cfg or {}).get("dashboard") or {}
    role = (dash.get("role") or "admin").lower()
    return role if role in ("admin", "viewer") else "admin"


def can_control(cfg: dict) -> bool:
    dash = (cfg or {}).get("dashboard") or {}
    if not dash.get("allow_control", True):
        return False
    return get_role(cfg) == "admin"


def must_change_password(cfg: dict) -> bool:
    dash = (cfg or {}).get("dashboard") or {}
    pw = dash.get("password") or ""
    return pw in ("", "admin", "password", "changeme")
