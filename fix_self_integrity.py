#!/usr/bin/env python3
"""Exclude config.json from self-integrity; set version 2.9.4. Safe to re-run."""
from __future__ import annotations
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"

NEW_FN = r'''def self_integrity_check(logger=None):
    """Watch only the engine binary — config.json is expected to change."""
    critical = [Path(__file__).resolve()]
    current = {str(f): sha256_file(f) for f in critical if f.exists()}
    if not SELF_INTEGRITY_FILE.exists():
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(SELF_INTEGRITY_FILE, "w") as fh:
            json.dump(current, fh, indent=2)
        if logger:
            logger.info(f"{C.GREEN}\u2713{C.RESET} Self-integrity baseline created")
        return True
    try:
        with open(SELF_INTEGRITY_FILE) as fh:
            baseline = json.load(fh)
    except Exception:
        return False
    # Drop legacy config.json entries from older baselines (noise)
    baseline = {k: v for k, v in baseline.items() if not k.endswith("config.json")}
    tampered = [fp for fp, h in current.items() if fp in baseline and baseline[fp] != h]
    if tampered:
        if logger:
            logger.warning(f"{C.RED}\u26a0 SELF-INTEGRITY VIOLATION:{C.RESET} {tampered}")
        send_alert("SELF_INTEGRITY_VIOLATION", {"files": tampered}, logger)
        return False
    try:
        with open(SELF_INTEGRITY_FILE, "w") as fh:
            json.dump(current, fh, indent=2)
    except Exception:
        pass
    if logger:
        logger.info(f"{C.GREEN}\u2713{C.RESET} Self-integrity check passed")
    return True
'''


def main() -> None:
    if not ENGINE.exists():
        print("[!] no sentinel.py")
        return
    src = ENGINE.read_text()
    if "config.json is expected to change" in src:
        print("[=] self_integrity already fixed")
    else:
        src2 = re.sub(
            r"def self_integrity_check\(logger=None\):.*?(?=\n\ndef )",
            NEW_FN + "\n",
            src,
            count=1,
            flags=re.S,
        )
        if src2 == src:
            print("[!] could not replace self_integrity_check")
        else:
            src = src2
            print("[+] self_integrity fixed")
    src, n = re.subn(r'__version__\s*=\s*"[^"]+"', '__version__ = "2.9.4"', src, count=1)
    if n:
        print("[+] version 2.9.4")
    ENGINE.write_text(src)
    for base in (
        Path.home() / ".sentinel/data/self_integrity.json",
        Path(os.environ.get("SENTINEL_DIR", str(Path.home() / ".sentinel"))) / "data/self_integrity.json",
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


if __name__ == "__main__":
    main()
