#!/usr/bin/env python3
"""FEATURE 10 — Encrypted JSON stores + password-protected PDFs."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _key_file() -> Path:
    return _home() / "data" / ".store_key"

def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()

def ensure_key(passphrase: Optional[str] = None) -> bytes:
    env = os.environ.get("SENTINEL_STORE_KEY")
    if env:
        return derive_key(env)
    if passphrase:
        return derive_key(passphrase)
    kf = _key_file()
    kf.parent.mkdir(parents=True, exist_ok=True)
    if kf.exists():
        return base64.urlsafe_b64decode(kf.read_text().strip())
    key = os.urandom(32)
    kf.write_text(base64.urlsafe_b64encode(key).decode())
    try:
        os.chmod(kf, 0o600)
    except Exception:
        pass
    return key

def _xor_stream(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)

def encrypt_bytes(data: bytes, passphrase: Optional[str] = None) -> bytes:
    key = ensure_key(passphrase)
    try:
        from cryptography.fernet import Fernet
        fkey = base64.urlsafe_b64encode(key)
        return b"FERNET:" + Fernet(fkey).encrypt(data)
    except Exception:
        return b"XOR1:" + _xor_stream(data, key)

def decrypt_bytes(blob: bytes, passphrase: Optional[str] = None) -> bytes:
    key = ensure_key(passphrase)
    if blob.startswith(b"FERNET:"):
        from cryptography.fernet import Fernet
        fkey = base64.urlsafe_b64encode(key)
        return Fernet(fkey).decrypt(blob[7:])
    if blob.startswith(b"XOR1:"):
        return _xor_stream(blob[5:], key)
    return blob

def write_encrypted_json(path: Path, obj: Any, passphrase: Optional[str] = None) -> None:
    raw = json.dumps(obj, indent=2).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encrypt_bytes(raw, passphrase))
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def read_encrypted_json(path: Path, passphrase: Optional[str] = None) -> Any:
    if not path.exists():
        return None
    data = path.read_bytes()
    if data[:1] in (b"{", b"["):
        return json.loads(data.decode())
    return json.loads(decrypt_bytes(data, passphrase).decode())

def protect_pdf(src: Path, password: str, dest: Optional[Path] = None) -> dict:
    dest = dest or src.with_suffix(".protected.pdf")
    try:
        from pikepdf import Pdf, Encryption
        pdf = Pdf.open(src)
        pdf.save(dest, encryption=Encryption(owner=password, user=password, R=6))
        pdf.close()
        return {"ok": True, "path": str(dest)}
    except ImportError:
        return {"ok": False, "error": "pip install pikepdf for password-protected PDFs"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def status() -> dict:
    kf = _key_file()
    return {
        "key_file_exists": kf.exists(),
        "env_key": bool(os.environ.get("SENTINEL_STORE_KEY")),
        "fernet_available": _fernet_ok(),
        "pikepdf_available": _pike_ok(),
    }

def _fernet_ok() -> bool:
    try:
        from cryptography.fernet import Fernet  # noqa
        return True
    except Exception:
        return False

def _pike_ok() -> bool:
    try:
        import pikepdf  # noqa
        return True
    except Exception:
        return False
