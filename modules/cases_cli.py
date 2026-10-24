# © 2026 TrinTech Digital Defense — authorized defensive use only
"""CLI for Phase 7 case / triage workflow."""
from __future__ import annotations

import argparse
import json
import sys

from modules import cases


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SENTINEL cases (Phase 7)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_c = sub.add_parser("create", help="Create a case")
    p_c.add_argument("--title", required=True)
    p_c.add_argument("--severity", default="medium")
    p_c.add_argument("--source", default="")
    p_c.add_argument("--source-event-id", default="")
    p_c.add_argument("--assignee", default="")
    p_c.add_argument("--summary", default="")
    p_c.add_argument("--actor", default="operator")

    p_l = sub.add_parser("list", help="List cases")
    p_l.add_argument("--status", default=None)
    p_l.add_argument("--assignee", default=None)
    p_l.add_argument("--limit", type=int, default=50)

    p_g = sub.add_parser("get", help="Get case detail")
    p_g.add_argument("case_id")

    p_s = sub.add_parser("status", help="Set case status")
    p_s.add_argument("case_id")
    p_s.add_argument("status", choices=list(cases.STATUSES))
    p_s.add_argument("--actor", default="operator")

    p_a = sub.add_parser("assign", help="Assign case")
    p_a.add_argument("case_id")
    p_a.add_argument("assignee")
    p_a.add_argument("--actor", default="operator")

    p_n = sub.add_parser("note", help="Add note")
    p_n.add_argument("case_id")
    p_n.add_argument("--body", required=True)
    p_n.add_argument("--author", default="operator")

    p_e = sub.add_parser("evidence", help="Export evidence pack")
    p_e.add_argument("case_id")
    p_e.add_argument("--out", default=None)
    p_e.add_argument("--actor", default="operator")

    p_att = sub.add_parser("attach", help="Attach alert ref to case")
    p_att.add_argument("case_id")
    p_att.add_argument("alert_ref")
    p_att.add_argument("--actor", default="operator")

    args = ap.parse_args(argv)

    if args.cmd == "create":
        r = cases.create_case(
            title=args.title,
            severity=args.severity,
            source=args.source,
            source_event_id=args.source_event_id,
            assignee=args.assignee,
            summary=args.summary,
            actor=args.actor,
        )
    elif args.cmd == "list":
        r = {"ok": True, "cases": cases.list_cases(status=args.status, assignee=args.assignee, limit=args.limit)}
    elif args.cmd == "get":
        c = cases.get_case(args.case_id)
        r = {"ok": bool(c), "case": c} if c else {"ok": False, "error": "not found"}
    elif args.cmd == "status":
        r = cases.set_status(args.case_id, args.status, actor=args.actor)
    elif args.cmd == "assign":
        r = cases.assign(args.case_id, args.assignee, actor=args.actor)
    elif args.cmd == "note":
        r = cases.add_note(args.case_id, args.body, author=args.author)
    elif args.cmd == "evidence":
        from pathlib import Path

        r = cases.export_evidence(args.case_id, out_dir=Path(args.out) if args.out else None, actor=args.actor)
    elif args.cmd == "attach":
        r = cases.attach_alert(args.case_id, args.alert_ref, actor=args.actor)
    else:
        return 1

    print(json.dumps(r, indent=2))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
