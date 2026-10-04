#!/usr/bin/env python3
"""Wire Phase 4 into sentinel.py"""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"
MOD = ROOT / "modules" / "phase4.py"
IMPORT = '''
# Phase 4 — Hard to Copy
try:
    from modules.phase4 import (
        baseline_build, baseline_check, caribbean_scan,
        playbook_get, playbook_list, evidence_pack,
        offline_enqueue, offline_status, offline_flush,
        phase4_self_check, ensure_phase4_defaults,
    )
except ImportError:
    baseline_build = lambda *a, **k: {"ok": False}
    baseline_check = lambda *a, **k: {"ok": False, "anomalies": []}
    caribbean_scan = lambda *a, **k: {"ok": False, "findings": []}
    playbook_get = lambda *a, **k: {"ok": False, "steps": []}
    playbook_list = lambda: []
    evidence_pack = lambda *a, **k: {"ok": False}
    offline_enqueue = lambda *a, **k: {"ok": False}
    offline_status = lambda: {"count": 0}
    offline_flush = lambda *a, **k: {"flushed": 0}
    phase4_self_check = lambda config: {"error": "phase4 missing"}
    ensure_phase4_defaults = lambda c: c or {}
'''
CLI = '''
    elif command == "baseline":
        config = ensure_phase4_defaults(config)
        if args and args[0] in ("check", "scan"):
            result = baseline_check(config)
            print(result)
        else:
            print(baseline_build(config))
    elif command == "caribbean":
        result = caribbean_scan(ensure_phase4_defaults(config))
        print(result)
    elif command == "playbook":
        if not args:
            for p in playbook_list():
                print(p)
        else:
            pb = playbook_get(args[0])
            print(pb.get("title"), pb.get("severity"))
            for s in pb.get("steps") or []:
                print(s)
    elif command == "evidence":
        hours = 24
        if "--hours" in args:
            i = args.index("--hours")
            if i+1 < len(args): hours = int(args[i+1])
        print(evidence_pack(hours=hours))
    elif command == "offline":
        if args and args[0] == "flush":
            print(offline_flush())
        else:
            print(offline_status())
    elif command == "phase4":
        config = ensure_phase4_defaults(config)
        print(phase4_self_check(config))
'''
def main():
    if not ENGINE.exists():
        print("[!] run assemble_engine.py first"); sys.exit(1)
    if not MOD.exists():
        print("[!] modules/phase4.py missing — git pull"); sys.exit(1)
    src = ENGINE.read_text()
    changed = False
    if "phase4_self_check" not in src or "from modules.phase4 import" not in src:
        for a in ["from typing import Optional", "__version__"]:
            if a in src:
                pos = src.find("\n", src.find(a)) + 1
                src = src[:pos] + IMPORT + "\n" + src[pos:]
                changed = True
                print("[+] imports")
                break
    if 'command == "baseline"' not in src:
        if 'elif command == "uninstall":' in src:
            src = src.replace('elif command == "uninstall":', CLI + '    elif command == "uninstall":')
            changed = True
            print("[+] CLI")
        elif 'else:' in src and 'Unknown command' in src:
            src = src.replace(
                'else:\n        logger.error',
                CLI + '    else:\n        logger.error'
            )
            changed = True
            print("[+] CLI via else")
    if '__version__ = "2.2.0"' in src:
        src = src.replace('__version__ = "2.2.0"', '__version__ = "2.5.0"')
        changed = True
    if changed:
        ENGINE.write_text(src)
        import py_compile
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] wired OK")
    else:
        print("[=] already wired or anchors missing")
    print("Try: python3 sentinel.py phase4")
if __name__ == "__main__":
    main()
