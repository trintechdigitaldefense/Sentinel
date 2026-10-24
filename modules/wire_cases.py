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
        import modules.phase9_hooks  # noqa: F401
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
    elif sub in ("digest-cron", "install-digest"):
        from modules.digest_cron import install

        hour, minute = 8, 0
        if rest:
            try:
                hour = int(rest[0])
                if len(rest) > 1:
                    minute = int(rest[1])
            except ValueError:
                pass
        print_fn(json.dumps(install(hour=hour, minute=minute), indent=2))
    elif sub == "digest-run":
        from modules.digest_cron import run_digest_job

        print_fn(json.dumps(run_digest_job(via="auto"), indent=2))
    elif sub == "connector-fetch":
        from modules.connector_enable import fetch_and_maybe_case

        source = rest[0] if rest else "sentinel_local"
        print_fn(json.dumps(fetch_and_maybe_case(source=source), indent=2))
    elif sub in ("correlate", "dual-pilot", "pilot"):
        from modules.dual_pilot import run_pilot, ensure_pilot_config

        if sub == "pilot" or (rest and rest[0] == "setup"):
            ensure_pilot_config()
        promote = "--no-promote" not in rest
        print_fn(json.dumps(run_pilot(promote=promote), indent=2, default=str))
    elif sub == "ai-summary":
        from modules.ai_assist import summarize_case

        cid = rest[0] if rest else ""
        print_fn(json.dumps(summarize_case(cid), indent=2))
    elif sub == "response-plan":
        from modules.gated_response import plan_for_case_id

        cid = rest[0] if rest else ""
        print_fn(json.dumps(plan_for_case_id(cid), indent=2))
    else:
        print_fn(f"Unknown cases subcommand: {sub}")
