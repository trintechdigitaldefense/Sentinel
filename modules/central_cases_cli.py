# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Master-side list of case summaries from central (Phase 10)."""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode


def _cfg() -> dict:
    p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def list_central_cases(
    central_url: Optional[str] = None,
    master_key: Optional[str] = None,
    client_id: str = "",
    limit: int = 100,
) -> dict:
    cfg = _cfg()
    central = cfg.get("central") or {}
    url = (central_url or central.get("server_url") or os.environ.get("SENTINEL_CENTRAL_URL") or "").rstrip("/")
    key = master_key or central.get("master_key") or os.environ.get("SENTINEL_MASTER_KEY") or ""
    if not url or not key:
        return {"ok": False, "error": "central_url and master_key required"}
    qs = urlencode({k: v for k, v in {"client_id": client_id, "limit": str(limit)}.items() if v})
    endpoint = f"{url}/v1/cases" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(
        endpoint,
        headers={
            "X-Sentinel-Key": key,
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
            return {"ok": True, "endpoint": endpoint, **body}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}", "detail": e.read().decode()[:500]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="List cases from SENTINEL central (master key)")
    ap.add_argument("--url", default=None)
    ap.add_argument("--master-key", default=None)
    ap.add_argument("--client-id", default="")
    ap.add_argument("--limit", type=int, default=100)
    args = ap.parse_args(argv)
    r = list_central_cases(
        central_url=args.url,
        master_key=args.master_key,
        client_id=args.client_id,
        limit=args.limit,
    )
    print(json.dumps(r, indent=2))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
