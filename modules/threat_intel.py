"""AbuseIPDB + OTX enrichment with 24h cache (feature 8)."""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.intel")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _cache_path() -> Path:
    return _home() / "data" / "intel_cache.json"


def _load_cache() -> dict:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_cache(c: dict) -> None:
    p = _cache_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(c))


def enrich_ip(ip: str, cfg: Optional[dict] = None) -> dict:
    cfg = cfg or {}
    if not cfg.get("enabled"):
        return {"ok": False, "skipped": True, "reason": "threat_intel disabled"}
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "empty ip"}

    cache_hours = float(cfg.get("cache_hours") or 24)
    cache = _load_cache()
    hit = cache.get(ip)
    if hit and (time.time() - float(hit.get("ts") or 0)) < cache_hours * 3600:
        hit["cached"] = True
        return hit

    result = {"ok": True, "ip": ip, "sources": {}, "malicious": False, "ts": time.time()}

    # AbuseIPDB
    key = cfg.get("abuseipdb_key") or ""
    if key:
        try:
            req = urllib.request.Request(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                headers={"Key": key, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=12) as r:
                data = json.loads(r.read().decode())
            score = (data.get("data") or {}).get("abuseConfidenceScore", 0)
            result["sources"]["abuseipdb"] = {"score": score}
            if score >= 50:
                result["malicious"] = True
        except Exception as e:
            result["sources"]["abuseipdb"] = {"error": str(e)}

    # OTX
    otx = cfg.get("otx_key") or ""
    if otx:
        try:
            req = urllib.request.Request(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": otx},
            )
            with urllib.request.urlopen(req, timeout=12) as r:
                data = json.loads(r.read().decode())
            pulse = (data.get("pulse_info") or {}).get("count", 0)
            result["sources"]["otx"] = {"pulses": pulse}
            if pulse >= 1:
                result["malicious"] = True
        except Exception as e:
            result["sources"]["otx"] = {"error": str(e)}

    if not key and not otx:
        result["ok"] = False
        result["error"] = "no API keys configured"

    cache[ip] = result
    _save_cache(cache)
    return result
