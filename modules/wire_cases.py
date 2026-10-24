# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Runtime wiring for cases integration.

Import this from sentinel after send_alert is defined, or call install_send_alert_hook.
Also handles `sentinel cases ...` subcommands.
"""
from __future__ import annotations


def install_send_alert_hook(send_alert_fn):
    """Wrap send_alert to auto-open cases. Returns wrapper."""

    def wrapped(alert_type, details, logger=None):
        result = send_alert_fn(alert_type, details, logger=logger)
        try:
            from modules.case_hooks import maybe_open_case_from_engine_alert

            maybe_open_case_from_engine_alert(
                alert_type, details if isinstance(details, dict) else {"raw": details}
            )
        except Exception:
            pass
        return result

    return wrapped


def cases_command(args, print_fn=print):
    """Handle `sentinel cases ...` subcommands."""
    import json

    try:
        import modules.phase9_hooks  # noqa: F401 — false_positive → suppression
    except Exception:
        pass

    from modules import cases as cases_mod

    sub = args[0] if args else "list"
    rest = args[1:] if args else []
    if sub == "list":
        rows = (
            cases_mod.list_cases(status="new", limit=30)
            + cases_mod.list_cases(status="triaging", limit=20)
            + cases_mod.list_cases(status="investigating", limit=20)
        )
        if not rows:
            print_fn("No open cases.")
            return
        for c in rows:
            print_fn(f"  {c['id']}  [{c['status']}/{c['severity']}]  {c['title'][:50]}")
    elif sub == "list-all":
        for c in cases_mod.list_cases(limit=50):
            print_fn(f"  {c['id']}  [{c['status']}/{c['severity']}]  {c['title'][:50]}")
    elif sub == "create":
        title = " ".join(rest) if rest else input("  Title: ").strip()
        print_fn(json.dumps(cases_mod.create_case(title=title, severity="high"), indent=2))
    elif sub == "get":
        cid = rest[0] if rest else input("  Case ID: ").strip()
        print_fn(json.dumps(cases_mod.get_case(cid), indent=2))
    elif sub == "status":
        cid = rest[0] if rest else input("  Case ID: ").strip()
        st = rest[1] if len(rest) > 1 else input(f"  Status {list(cases_mod.STATUSES)}: ").strip()
        print_fn(json.dumps(cases_mod.set_status(cid, st), indent=2))
    elif sub == "assign":
        cid = rest[0] if rest else input("  Case ID: ").strip()
        who = rest[1] if len(rest) > 1 else input("  Assignee: ").strip()
        print_fn(json.dumps(cases_mod.assign(cid, who), indent=2))
    elif sub == "note":
        cid = rest[0] if rest else input("  Case ID: ").strip()
        body = " ".join(rest[1:]) if len(rest) > 1 else input("  Note: ").strip()
        print_fn(json.dumps(cases_mod.add_note(cid, body), indent=2))
    elif sub == "evidence":
        cid = rest[0] if rest else input("  Case ID: ").strip()
        print_fn(json.dumps(cases_mod.export_evidence(cid), indent=2))
    elif sub in ("digest", "digest-send"):
        from modules.msp_digest import format_digest, send_digest

        if sub == "digest":
            print_fn(format_digest())
        else:
            print_fn(json.dumps(send_digest(via="auto"), indent=2))
    elif sub == "client-note":
        from modules.client_notes import save_client_note

        cid = rest[0] if rest else input("  Case ID: ").strip()
        name = rest[1] if len(rest) > 1 else "Client"
        r = save_client_note(cid, client_name=name)
        print_fn(r.get("note") if r.get("ok") else json.dumps(r, indent=2))
        if r.get("path"):
            print_fn(f"Saved: {r['path']}")
    elif sub == "sync":
        from modules.cases_sync import sync_open_cases_to_central

        print_fn(json.dumps(sync_open_cases_to_central(), indent=2))
    else:
        print_fn(f"Unknown cases subcommand: {sub}")
