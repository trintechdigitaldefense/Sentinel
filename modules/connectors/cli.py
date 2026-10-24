# © 2026 TrinTech Digital Defense — authorized defensive use only
"""CLI helpers for connectors (Phase 6).

Usage (from repo root or installed package):
  python3 -c "from modules.connectors.cli import main; main()" health
  python3 -c "from modules.connectors.cli import main; main()" fetch --source sentinel_local --limit 20
"""
from __future__ import annotations

import argparse
import json
import sys

from modules.connectors import get_connector


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SENTINEL connectors (Phase 6)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_h = sub.add_parser("health", help="Run health_check")
    p_h.add_argument("--source", default="sentinel_local", help="sentinel_local | wazuh")

    p_f = sub.add_parser("fetch", help="Fetch and print normalized alerts")
    p_f.add_argument("--source", default="sentinel_local")
    p_f.add_argument("--limit", type=int, default=20)
    p_f.add_argument("--cursor", default=None)
    p_f.add_argument("--since", default=None)
    p_f.add_argument("--url", default=None, help="Wazuh URL override")
    p_f.add_argument("--user", default=None, help="Wazuh user")
    p_f.add_argument("--password", default=None, help="Wazuh password")

    args = ap.parse_args(argv)
    cfg = {}
    if getattr(args, "url", None):
        cfg["url"] = args.url
    if getattr(args, "user", None):
        cfg["user"] = args.user
    if getattr(args, "password", None):
        cfg["password"] = args.password

    try:
        conn = get_connector(args.source, cfg)
    except ValueError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2

    if args.cmd == "health":
        h = conn.health_check()
        print(json.dumps(h.to_dict(), indent=2))
        return 0 if h.ok else 1

    if args.cmd == "fetch":
        alerts, nxt = conn.fetch_events(cursor=args.cursor, since=args.since, limit=args.limit)
        print(
            json.dumps(
                {
                    "ok": True,
                    "source": conn.name,
                    "count": len(alerts),
                    "next_cursor": nxt,
                    "alerts": [a.to_dict() for a in alerts],
                },
                indent=2,
            )
        )
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
