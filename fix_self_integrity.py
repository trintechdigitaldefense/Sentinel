#!/usr/bin/env python3
"""Exclude config.json from self-integrity; bump version. Safe to re-run."""
from __future__ import annotations
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"
VERSION = "2.9.9"

NEW_FN = (
    "def self_integrity_check(logger=None):\n"
    '    """Watch only the engine binary — config.json is expected to change."""\n'
    "    critical = [Path(__file__).resolve()]\n"
    "    current = {str(f): sha256_file(f) for f in critical if f.exists()}\n"
    "    if not SELF_INTEGRITY_FILE.exists():\n"
    "        DATA_DIR.mkdir(parents=True, exist_ok=True)\n"
    "        with open(SELF_INTEGRITY_FILE, \"w\") as fh:\n"
    "            json.dump(current, fh, indent=2)\n"
    "        if logger:\n"
    "            logger.info(f\"{C.GREEN}\\u2713{C.RESET} Self-integrity baseline created\")\n"
    "        return True\n"
    "    try:\n"
    "        with open(SELF_INTEGRITY_FILE) as fh:\n"
    "            baseline = json.load(fh)\n"
    "    except Exception:\n"
    "        return False\n"
    "    baseline = {k: v for k, v in baseline.items() if not k.endswith(\"config.json\")}\n"
    "    tampered = [fp for fp, h in current.items() if fp in baseline and baseline[fp] != h]\n"
    "    if tampered:\n"
    "        if logger:\n"
    "            logger.warning(f\"{C.RED}\\u26a0 SELF-INTEGRITY VIOLATION:{C.RESET} {tampered}\")\n"
    "        send_alert(\"SELF_INTEGRITY_VIOLATION\", {\"files\": tampered}, logger)\n"
    "        return False\n"
    "    try:\n"
    "        with open(SELF_INTEGRITY_FILE, \"w\") as fh:\n"
    "            json.dump(current, fh, indent=2)\n"
    "    except Exception:\n"
    "        pass\n"
    "    if logger:\n"
    "        logger.info(f\"{C.GREEN}\\u2713{C.RESET} Self-integrity check passed\")\n"
    "    return True\n"
)


def main() -> int:
    if not ENGINE.exists():
        print("[!] no sentinel.py")
        return 1
    src = ENGINE.read_text()
    if "config.json is expected to change" in src:
        print("[=] self_integrity already fixed")
    else:

        def _repl(_m):
            return NEW_FN + "\n\n"

        src2, n = re.subn(
            r"def self_integrity_check\(logger=None\):.*?(?=\n\ndef )",
            _repl,
            src,
            count=1,
            flags=re.S,
        )
        if n == 0:
            print("[!] could not replace self_integrity_check")
            return 1
        src = src2
        print("[+] self_integrity fixed")
    src, n = re.subn(
        r'__version__\s*=\s*"[^"]+"',
        f'__version__ = "{VERSION}"',
        src,
        count=1,
    )
    if n:
        print(f"[+] version {VERSION}")
    ENGINE.write_text(src)
    for base in (
        Path.home() / ".sentinel/data/self_integrity.json",
        Path(os.environ.get("SENTINEL_DIR", str(Path.home() / ".sentinel")))
        / "data/self_integrity.json",
    ):
        try:
            if base.exists():
                base.unlink()
                print(f"[+] cleared {base}")
        except Exception:
            pass
    import py_compile

    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] Syntax OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
