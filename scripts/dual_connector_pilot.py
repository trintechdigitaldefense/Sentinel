#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""CLI: dual-connector pilot (Sentinel-local + Wazuh)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL dual-connector pilot")
    ap.add_argument("--setup", action="store_true", help="Write pilot config defaults")
    ap.add_argument("--window", type=int, default=None, help="Correlation window minutes")
    ap.add_argument("--no-promote", action="store_true")
    ap.add_argument("--no-lab", action="store_true", help="Disable synthetic lab alerts")
    ap.add_argument("--ai-key", default="", help="Lab-only OpenAI-compatible API key")
    args = ap.parse_args()

    from modules.dual_pilot import ensure_pilot_config, run_pilot

    if args.setup or args.ai_key:
        cfg = ensure_pilot_config(
            window_minutes=args.window or 45,
            lab_mode=not args.no_lab,
            ai_enabled=bool(args.ai_key),
            ai_api_key=args.ai_key,
        )
        print(
            json.dumps(
                {
                    "setup": True,
                    "correlation": cfg.get("correlation"),
                    "ai_enabled": (cfg.get("ai") or {}).get("enabled"),
                },
                indent=2,
            )
        )

    result = run_pilot(
        window_minutes=args.window,
        promote=not args.no_promote,
        lab_mode=False if args.no_lab else None,
        inject_lab_alerts=not args.no_lab,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
