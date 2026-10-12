#!/usr/bin/env python3
"""Tighten process_scan malware_path checks — no more /tmp substring false positives."""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"

OLD = '''            for mpath in pm.get("malware_paths", []):
                if mpath in command:
                    msg = f"{C.RED}\u26a0 PROCESS FROM MALWARE PATH:{C.RESET} {C.BOLD}{command[:80]}{C.RESET}"
                    logger.warning(msg)
                    suspicious.append({"pid": pid, "user": user, "command": command, "reason": "malware_path"})
                    send_alert("MALWARE_PATH_PROCESS", {"pid": pid, "user": user, "command": command[:200], "path": mpath}, logger)
                    break
'''

NEW = '''            # Only flag if the *executable* lives under a malware path — not if
            # the command line merely mentions /tmp (e.g. curl writing a file there).
            exe = command.split()[0] if command.split() else ""
            allow_bin = pm.get("allowlist_bins", [
                "curl", "wget", "git", "ssh", "scp", "rsync", "python", "python3",
                "bash", "sh", "dash", "zsh", "node", "npm", "pip", "pip3", "apt",
                "dpkg", "systemctl", "journalctl", "ps", "top", "htop", "ss", "ip",
            ])
            exe_base = exe.rsplit("/", 1)[-1]
            system_prefixes = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/")
            if any(exe.startswith(p) for p in system_prefixes) or exe_base in allow_bin:
                pass  # skip malware_path check for known-good
            else:
                for mpath in pm.get("malware_paths", ["/tmp/", "/var/tmp/", "/dev/shm/"]):
                    if exe.startswith(mpath) or (mpath.rstrip("/") and exe.startswith(mpath.rstrip("/"))):
                        msg = f"{C.RED}\u26a0 PROCESS FROM MALWARE PATH:{C.RESET} {C.BOLD}{command[:80]}{C.RESET}"
                        logger.warning(msg)
                        suspicious.append({"pid": pid, "user": user, "command": command, "reason": "malware_path", "exe": exe})
                        send_alert("MALWARE_PATH_PROCESS", {"pid": pid, "user": user, "command": command[:200], "path": mpath, "exe": exe}, logger)
                        break
'''

def main():
    if not ENGINE.exists():
        print("[!] no sentinel.py"); return
    src = ENGINE.read_text()
    if "Only flag if the *executable* lives under a malware path" in src:
        print("[=] process_scan already fixed")
        return
    # Try exact match; also tolerate already-fixed or slightly different spacing
    if OLD in src:
        ENGINE.write_text(src.replace(OLD, NEW))
    elif "if mpath in command:" in src and "malware_paths" in src:
        import re
        src2 = re.sub(
            r"[ ]{12}for mpath in pm\.get\(\"malware_paths\"[^\n]+\n(?:[ ]{16}[^\n]+\n){5}",
            NEW,
            src,
            count=1,
        )
        if src2 == src:
            print("[!] could not patch malware_path block")
            return
        ENGINE.write_text(src2)
    else:
        print("[!] malware_path block not found")
        return
    import py_compile
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] process_scan malware_path fixed")
    print("[+] Syntax OK")

if __name__ == "__main__":
    main()
