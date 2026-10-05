#!/usr/bin/env python3
"""Clean banner: SENTINEL only, no hybrid old logo, no escape warnings."""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

ART_LINES = [
    r"  ____  _____ _   _ _____ ___ _   _ _____ _",
    r" / ___|| ____| \ | |_   _|_ _| \ | | ____| |",
    r" \___ \|  _| |  \| | | |  | ||  \| |  _| | |",
    r"  ___) | |___| |\  | | |  | || |\  | |___| |___",
    r" |____/|_____|_| \_| |_| |___|_| \_|_____|_____|",
]


def main():
    src = ENGINE.read_text()

    src = re.sub(
        r"\ndef print_banner\([^)]*\):.*?(?=\n(?:def |class |\nif __name__))",
        "\n",
        src,
        flags=re.DOTALL,
    )
    src = re.sub(
        r"^def print_banner\([^)]*\):.*?(?=\n(?:def |class |\nif __name__))",
        "",
        src,
        count=1,
        flags=re.DOTALL | re.MULTILINE,
    )

    out = []
    for line in src.splitlines(True):
        s = line.rstrip("\n")
        if re.match(r"^  _   _\s+_   _", s):
            continue
        if re.match(r"^ \| \\ \| \|", s) and "____" not in s:
            continue
        if re.match(r"^ \|  \\\| \|", s):
            continue
        if re.match(r"^ \| \. ` \|", s):
            continue
        if re.match(r"^ \| \|\\  \|", s):
            continue
        if re.match(r"^ \|_| \\\|_\|", s) and "____" not in s:
            continue
        if re.match(r"^ \|_|  ____", s):
            continue
        out.append(line)
    src = "".join(out)

    art_py = " + \"\\n\" + ".join(repr(x) for x in ART_LINES)
    fn = f'''
def print_banner():
    """SENTINEL banner only."""
    art = {art_py}
    print(f"{{C.CYAN}}{{C.BOLD}}\\n{{art}}\\n{{C.RESET}}")
    try:
        ver = __version__
    except Exception:
        ver = "2.5.0"
    print(f"{{C.BOLD}}  SENTINEL v{{ver}}{{C.RESET}}")
    print(f"{{C.GRAY}}  TrinTech Digital Defense — Active Deception · Persistence Hunting · Line of Defense{{C.RESET}}")
    print(f"{{C.GRAY}}  " + ("─" * 66) + f"{{C.RESET}}\\n")

'''

    idx = src.find("\ndef main(")
    if idx < 0:
        idx = src.find("def main(")
    if idx < 0:
        print("[!] main() not found")
        sys.exit(1)
    src = src[:idx] + "\n" + fn + "\n" + src[idx:]

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Clean SENTINEL banner — syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax: {e}")
        sys.exit(1)

    p = Path.home() / ".sentinel/data/self_integrity.json"
    if p.exists():
        p.unlink()
        print("[+] Integrity baseline cleared")
    print("Test:  python3 sentinel.py start")


if __name__ == "__main__":
    main()
