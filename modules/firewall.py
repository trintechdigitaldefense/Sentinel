# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Sentinel Host Firewall Control Plane (Phase 13).

This is a HOST firewall manager (iptables/nftables on the machine running
Sentinel). It is NOT a network perimeter appliance (pfSense/FortiGate).

Safety:
- dry_run default for destructive changes unless confirm=True
- every change audited to ~/.sentinel/data/firewall_audit.jsonl
- profiles stored under ~/.sentinel/data/firewall/
- never flushes all rules unless explicit confirm + --danger-flush
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data" / "firewall"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _audit_path() -> Path:
    p = _home() / "data" / "firewall_audit.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(action: str, detail: dict, ok: bool = True) -> None:
    rec = {"ts": _now(), "action": action, "ok": ok, "detail": detail}
    with open(_audit_path(), "a") as f:
        f.write(json.dumps(rec) + "\n")


def _run(cmd: list[str], timeout: int = 15) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "ok": r.returncode == 0,
            "code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip(),
            "cmd": cmd,
        }
    except FileNotFoundError:
        return {"ok": False, "code": 127, "stdout": "", "stderr": f"not found: {cmd[0]}", "cmd": cmd}
    except Exception as e:
        return {"ok": False, "code": -1, "stdout": "", "stderr": str(e), "cmd": cmd}


def backend() -> str:
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables"):
        return "iptables"
    return "none"


def status() -> dict:
    b = backend()
    out: dict[str, Any] = {
        "ok": True,
        "backend": b,
        "note": "Host firewall control — not a perimeter network firewall",
        "dry_run_default": True,
    }
    if b == "none":
        out["ok"] = False
        out["error"] = "neither nft nor iptables found"
        return out
    if b == "nft":
        r = _run(["nft", "list", "ruleset"])
        out["ruleset_preview"] = "\n".join((r.get("stdout") or "").splitlines()[:40])
        out["ruleset_ok"] = r["ok"]
    else:
        r = _run(["iptables", "-L", "-n", "-v"])
        out["ruleset_preview"] = "\n".join((r.get("stdout") or "").splitlines()[:40])
        out["ruleset_ok"] = r["ok"]
    blocks = _load_blocks()
    out["managed_blocks"] = len(blocks.get("ips") or [])
    out["managed_port_allows"] = len(blocks.get("ports_allow") or [])
    out["profile"] = blocks.get("profile") or "default"
    return out


def _blocks_path() -> Path:
    return _data() / "managed_blocks.json"


def _load_blocks() -> dict:
    p = _blocks_path()
    if not p.exists():
        return {"ips": [], "ports_allow": [], "ports_deny": [], "profile": "default", "updated": _now()}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"ips": [], "ports_allow": [], "ports_deny": [], "profile": "default", "updated": _now()}


def _save_blocks(data: dict) -> None:
    data["updated"] = _now()
    _blocks_path().write_text(json.dumps(data, indent=2))


_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")


def _valid_ip(ip: str) -> bool:
    ip = (ip or "").strip()
    if not ip or ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return False
    if not _IP_RE.match(ip):
        return False
    if "." in ip:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return True


def block_ip(ip: str, confirm: bool = False, reason: str = "") -> dict:
    ip = (ip or "").strip()
    if not _valid_ip(ip):
        return {"ok": False, "error": "invalid or refused IP", "ip": ip}
    b = backend()
    if not confirm:
        _audit("block_ip_dry_run", {"ip": ip, "reason": reason, "backend": b})
        return {
            "ok": True,
            "dry_run": True,
            "would": f"block {ip} on INPUT",
            "backend": b,
            "hint": "pass confirm=True to apply",
        }
    if b == "none":
        return {"ok": False, "error": "no firewall backend"}
    if b == "nft":
        _run(["nft", "add", "table", "inet", "sentinel"])
        _run(["nft", "add", "chain", "inet", "sentinel", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"])
        if ":" in ip:
            r = _run(["nft", "insert", "rule", "inet", "sentinel", "input", "ip6", "saddr", ip, "drop"])
        else:
            r = _run(["nft", "insert", "rule", "inet", "sentinel", "input", "ip", "saddr", ip, "drop"])
    else:
        r = _run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "sentinel-block"])
    data = _load_blocks()
    if ip not in data["ips"]:
        data["ips"].append(ip)
        _save_blocks(data)
    _audit("block_ip", {"ip": ip, "reason": reason, "backend": b, "result": r}, ok=r.get("ok", False))
    return {"ok": r.get("ok", False), "ip": ip, "backend": b, "applied": True, "detail": r}


def unblock_ip(ip: str, confirm: bool = False) -> dict:
    ip = (ip or "").strip()
    if not confirm:
        return {"ok": True, "dry_run": True, "would": f"unblock {ip}"}
    b = backend()
    results = []
    if b == "iptables":
        for _ in range(5):
            r = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            results.append(r)
            if not r["ok"]:
                break
    elif b == "nft":
        results.append(_run(["nft", "list", "table", "inet", "sentinel"]))
    data = _load_blocks()
    data["ips"] = [x for x in data.get("ips") or [] if x != ip]
    _save_blocks(data)
    _audit("unblock_ip", {"ip": ip, "results": results})
    return {"ok": True, "ip": ip, "applied": True, "note": "removed from managed list; verify with status"}


def allow_port(port: int, proto: str = "tcp", confirm: bool = False) -> dict:
    try:
        port = int(port)
    except Exception:
        return {"ok": False, "error": "bad port"}
    if port < 1 or port > 65535:
        return {"ok": False, "error": "port out of range"}
    proto = (proto or "tcp").lower()
    if proto not in ("tcp", "udp"):
        return {"ok": False, "error": "proto must be tcp or udp"}
    if not confirm:
        return {"ok": True, "dry_run": True, "would": f"allow {proto}/{port} INPUT", "backend": backend()}
    b = backend()
    if b == "none":
        return {"ok": False, "error": "no firewall backend"}
    if b == "iptables":
        r = _run(["iptables", "-I", "INPUT", "1", "-p", proto, "--dport", str(port), "-j", "ACCEPT", "-m", "comment", "--comment", "sentinel-allow-port"])
    else:
        _run(["nft", "add", "table", "inet", "sentinel"])
        r = _run(["nft", "insert", "rule", "inet", "sentinel", "input", proto, "dport", str(port), "accept"])
    data = _load_blocks()
    key = f"{proto}/{port}"
    if key not in (data.get("ports_allow") or []):
        data.setdefault("ports_allow", []).append(key)
        _save_blocks(data)
    _audit("allow_port", {"port": port, "proto": proto, "result": r}, ok=r.get("ok", False))
    return {"ok": r.get("ok", False), "port": port, "proto": proto, "applied": True}


def deny_port(port: int, proto: str = "tcp", confirm: bool = False) -> dict:
    try:
        port = int(port)
    except Exception:
        return {"ok": False, "error": "bad port"}
    if not confirm:
        return {"ok": True, "dry_run": True, "would": f"deny {proto}/{port} INPUT", "backend": backend()}
    b = backend()
    if b == "none":
        return {"ok": False, "error": "no firewall backend"}
    if b == "iptables":
        r = _run(["iptables", "-I", "INPUT", "1", "-p", proto, "--dport", str(port), "-j", "DROP", "-m", "comment", "--comment", "sentinel-deny-port"])
    else:
        r = _run(["nft", "insert", "rule", "inet", "sentinel", "input", proto, "dport", str(port), "drop"])
    data = _load_blocks()
    key = f"{proto}/{port}"
    data.setdefault("ports_deny", []).append(key)
    _save_blocks(data)
    _audit("deny_port", {"port": port, "proto": proto, "result": r}, ok=r.get("ok", False))
    return {"ok": r.get("ok", False), "port": port, "proto": proto, "applied": True}


PROFILES = {
    "default": {"description": "Track managed blocks only; do not change policy", "actions": []},
    "hardening": {
        "description": "Deny common risky inbound (135,139,445,3389) if not needed",
        "deny_ports": [(135, "tcp"), (139, "tcp"), (445, "tcp"), (3389, "tcp")],
    },
    "web_server": {"description": "Allow 80/443 tcp", "allow_ports": [(80, "tcp"), (443, "tcp")]},
    "ssh_only": {"description": "Allow 22 tcp (ensure you have console access first)", "allow_ports": [(22, "tcp")]},
}


def list_profiles() -> dict:
    return {"ok": True, "profiles": PROFILES}


def apply_profile(name: str, confirm: bool = False) -> dict:
    name = (name or "").strip().lower()
    if name not in PROFILES:
        return {"ok": False, "error": "unknown profile", "available": list(PROFILES)}
    prof = PROFILES[name]
    if not confirm:
        return {"ok": True, "dry_run": True, "profile": name, "would_apply": prof}
    results = []
    for port, proto in prof.get("deny_ports") or []:
        results.append(deny_port(port, proto, confirm=True))
    for port, proto in prof.get("allow_ports") or []:
        results.append(allow_port(port, proto, confirm=True))
    data = _load_blocks()
    data["profile"] = name
    _save_blocks(data)
    _audit("apply_profile", {"profile": name, "results": results})
    return {"ok": True, "profile": name, "results": results, "applied": True}


def backup_rules() -> dict:
    b = backend()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = _data() / f"rules_backup_{ts}.txt"
    if b == "nft":
        r = _run(["nft", "list", "ruleset"])
    elif b == "iptables":
        r = _run(["iptables-save"]) if shutil.which("iptables-save") else _run(["iptables", "-L", "-n", "-v"])
    else:
        return {"ok": False, "error": "no backend"}
    path.write_text(r.get("stdout") or "")
    _audit("backup_rules", {"path": str(path), "backend": b})
    return {"ok": True, "path": str(path), "backend": b, "bytes": path.stat().st_size}


def list_managed() -> dict:
    return {"ok": True, **_load_blocks()}


def audit_tail(n: int = 20) -> dict:
    p = _audit_path()
    if not p.exists():
        return {"ok": True, "events": []}
    lines = p.read_text().splitlines()[-n:]
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except Exception:
            pass
    return {"ok": True, "events": events}


def doctor() -> dict:
    st = status()
    issues = []
    if st.get("backend") == "none":
        issues.append({"severity": "high", "issue": "No nft/iptables backend on host"})
    elif not st.get("ruleset_ok"):
        issues.append({"severity": "medium", "issue": "Could not list ruleset (need root?)"})
    return {
        "ok": len([i for i in issues if i["severity"] == "high"]) == 0,
        "backend": st.get("backend"),
        "managed_blocks": st.get("managed_blocks"),
        "issues": issues,
        "note": st.get("note"),
    }


def cli(argv: list[str]) -> int:
    if not argv:
        print(json.dumps(status(), indent=2))
        return 0
    cmd = argv[0]
    rest = argv[1:]
    if cmd == "status":
        print(json.dumps(status(), indent=2))
    elif cmd == "block":
        ip = rest[0] if rest else ""
        conf = "--confirm" in rest
        print(json.dumps(block_ip(ip, confirm=conf), indent=2))
    elif cmd == "unblock":
        ip = rest[0] if rest else ""
        conf = "--confirm" in rest
        print(json.dumps(unblock_ip(ip, confirm=conf), indent=2))
    elif cmd == "allow-port":
        port = int(rest[0]) if rest else 0
        conf = "--confirm" in rest
        print(json.dumps(allow_port(port, confirm=conf), indent=2))
    elif cmd == "deny-port":
        port = int(rest[0]) if rest else 0
        conf = "--confirm" in rest
        print(json.dumps(deny_port(port, confirm=conf), indent=2))
    elif cmd == "profiles":
        print(json.dumps(list_profiles(), indent=2))
    elif cmd == "profile":
        name = rest[0] if rest else "default"
        conf = "--confirm" in rest
        print(json.dumps(apply_profile(name, confirm=conf), indent=2))
    elif cmd == "backup":
        print(json.dumps(backup_rules(), indent=2))
    elif cmd == "managed":
        print(json.dumps(list_managed(), indent=2))
    elif cmd == "audit":
        print(json.dumps(audit_tail(30), indent=2))
    elif cmd == "doctor":
        print(json.dumps(doctor(), indent=2))
    else:
        print(f"unknown firewall command: {cmd}")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(cli(sys.argv[1:]))
