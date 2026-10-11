#!/usr/bin/env python3
"""SENTINEL rebuild_hooks — restore hunt loop + hooks ONLY on hunt/central."""
from __future__ import annotations
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"

HOOKS = """                # --- Sentinel hooks (auto) ---
                try:
                    from modules.phase5 import heartbeat_from_hunt
                    heartbeat_from_hunt()
                except Exception:
                    pass
                try:
                    from modules.deadman import emit_heartbeat as _dm_emit, check_fleet as _dm_fleet
                    _dm_emit("hunt")
                    _dm_fleet()
                except Exception:
                    pass
                try:
                    from modules.usb_watch import check as _usb_check
                    _usb_check()
                except Exception:
                    pass
                try:
                    from modules.lateral import check as _lat_check
                    _lat_check()
                except Exception:
                    pass
                try:
                    from modules.dns_watch import check as _dns_check
                    _dns_check()
                except Exception:
                    pass
                try:
                    from modules.device_radar import check as _radar_check
                    _radar_check()
                except Exception:
                    pass
                try:
                    from modules.ransomware_tripwire import check as _tw_check
                    _tw_check()
                except Exception:
                    pass
                try:
                    from modules.honeyauth import check as _honey_check
                    _honey_check()
                except Exception:
                    pass
                # --- end hooks ---
"""

def _fix_integrity_colon(src: str) -> str:
    src = re.sub(r'(elif command == "integrity")\s*\n', r'\1:\n', src)
    lines = src.splitlines(keepends=True)
    out = []
    for i, line in enumerate(lines):
        if line.strip() == ":" and i > 0 and "integrity" in lines[i - 1]:
            continue
        out.append(line)
    return "".join(out)

def main() -> None:
    if not ENGINE.exists():
        print("[!] sentinel.py missing", file=sys.stderr)
        sys.exit(1)
    src = ENGINE.read_text()
    backup = ENGINE.with_suffix(".py.bak_hooks")
    backup.write_text(src)
    print(f"[+] backup: {backup.name}")
    src = _fix_integrity_colon(src)

    hunt_body = (
        '    elif command == "hunt":\n'
        '        data = load_devices()\n'
        '        logger.info(f"{C.CYAN}[*]{C.RESET} Persistence hunting \u2014 Ctrl+C to stop")\n'
        '        interval = config.get("persistence", {}).get("monitor_interval", 60)\n'
        '        try:\n'
        '            while True:\n'
        + HOOKS
        + '                try:\n'
        '                    persistence_hunt(config, logger)\n'
        '                except Exception as _ph_err:\n'
        '                    logger.warning(f"! persistence_hunt error: {_ph_err}")\n'
        '                time.sleep(max(10, int(interval) if interval else 60))\n'
        '        except KeyboardInterrupt:\n'
        '            logger.info(f"{C.GREEN}\u2713{C.RESET} Persistence hunting stopped")\n'
        '\n'
    )
    central_body = (
        '    elif command == "central":\n'
        '        start_central_listener(logger)\n'
        '        logger.info(f"{C.CYAN}[*]{C.RESET} Central mode \u2014 listening for agents + local hunt")\n'
        '        interval = config.get("persistence", {}).get("monitor_interval", 60)\n'
        '        try:\n'
        '            while True:\n'
        '                # --- Sentinel hooks (auto) ---\n'
        '                try:\n'
        '                    from modules.phase5 import heartbeat_from_hunt\n'
        '                    heartbeat_from_hunt()\n'
        '                except Exception:\n'
        '                    pass\n'
        '                try:\n'
        '                    from modules.deadman import emit_heartbeat as _dm_emit, check_fleet as _dm_fleet\n'
        '                    _dm_emit("central")\n'
        '                    _dm_fleet()\n'
        '                except Exception:\n'
        '                    pass\n'
        '                # --- end hooks ---\n'
        '                try:\n'
        '                    persistence_hunt(config, logger)\n'
        '                except Exception as _ph_err:\n'
        '                    logger.warning(f"! persistence_hunt error: {_ph_err}")\n'
        '                time.sleep(max(10, int(interval) if interval else 60))\n'
        '        except KeyboardInterrupt:\n'
        '            logger.info(f"{C.GREEN}\u2713{C.RESET} Central mode stopped")\n'
        '\n'
    )

    hunt_pat = re.compile(r'^    elif command == "hunt":.*?(?=^    elif command )', re.M | re.S)
    if not hunt_pat.search(src):
        print("[!] could not find hunt block", file=sys.stderr)
        sys.exit(1)
    src = hunt_pat.sub(hunt_body, src, count=1)
    print("[+] hunt loop restored + hooks on hunt")

    central_pat = re.compile(r'^    elif command == "central":.*?(?=^    elif command )', re.M | re.S)
    if central_pat.search(src):
        src = central_pat.sub(central_body, src, count=1)
        print("[+] central cleaned (short hooks + persistence_hunt)")
    else:
        print("[=] no central block")

    src = _fix_integrity_colon(src)
    ENGINE.write_text(src)
    import py_compile
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Syntax OK")
    except py_compile.PyCompileError as e:
        print("[!] Syntax error:", e)
        sys.exit(1)

    text = ENGINE.read_text()
    h = text.find('elif command == "hunt"')
    e = text.find('elif command == "config"', h)
    chunk = text[h:e] if e > h else text[h:h+3000]
    if "while True:" in chunk and "persistence_hunt" in chunk:
        print("[+] VERIFY hunt OK (while True + persistence_hunt)")
    else:
        print("[!] VERIFY hunt FAILED")
        print(chunk[:600])
        sys.exit(1)
    print("\nNext:\n  python3 sentinel.py hunt\n  python3 go.py")

if __name__ == "__main__":
    main()
