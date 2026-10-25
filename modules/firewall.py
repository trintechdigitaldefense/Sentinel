# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Sentinel Host Firewall Control Plane (Phase 13.1 enhanced).

HOST firewall manager (nftables preferred, iptables fallback).
NOT a perimeter/router appliance.

Safety: dry-run unless confirm; audit log; max_blocks; refuse loopback.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "13.2.0"


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


def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text()).get("firewall") or {}
        except Exception:
            pass
    return {}


def _audit(action: str, detail: dict, ok: bool = True) -> None:
    rec = {"ts": _now(), "action": action, "ok": ok, "detail": detail, "version": VERSION}
    with open(_audit_path(), "a") as f:
        f.write(json.dumps(rec) + "\n")


def _run(cmd: list[str], timeout: int = 20) -> dict:
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
    prefer = (_cfg().get("backend") or "auto").lower()
    if prefer == "nft" and shutil.which("nft"):
        return "nft"
    if prefer == "iptables" and shutil.which("iptables"):
        return "iptables"
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables"):
        return "iptables"
    return "none"


def _blocks_path() -> Path:
    return _data() / "managed_blocks.json"


def _load_blocks() -> dict:
    p = _blocks_path()
    default = {
        "ips": [],
        "cidrs": [],
        "ports_allow": [],
        "ports_deny": [],
        "profile": "default",
        "enabled": True,
        "updated": _now(),
    }
    if not p.exists():
        return default
    try:
        data = json.loads(p.read_text())
        for k, v in default.items():
            data.setdefault(k, v)
        return data
    except Exception:
        return default


def _save_blocks(data: dict) -> None:
    data["updated"] = _now()
    _blocks_path().write_text(json.dumps(data, indent=2))


def _max_blocks() -> int:
    try:
        return int(_cfg().get("max_blocks") or 200)
    except Exception:
        return 200


def _parse_target(target: str) -> tuple[str, str]:
    t = (target or "").strip()
    if not t:
        raise ValueError("empty target")
    low = t.lower()
    if low in ("0.0.0.0", "::", "127.0.0.1", "::1", "localhost"):
        raise ValueError("refused localhost/unspecified")
    if "/" in t:
        net = ipaddress.ip_network(t, strict=False)
        if net.is_loopback or net.is_unspecified:
            raise ValueError("refused loopback/unspecified net")
        if net.prefixlen == 0:
            raise ValueError("refused /0")
        return "cidr", str(net)
    ip = ipaddress.ip_address(t)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise ValueError("refused loopback/unspecified/multicast")
    return "ip", str(ip)




def detect_operator_ips() -> list[str]:
    """IPs of the current operator session (SSH client) — never block these."""
    found: set[str] = set()
    for env in ("SSH_CLIENT", "SSH_CONNECTION"):
        v = (os.environ.get(env) or "").strip()
        if not v:
            continue
        part = v.split()[0]
        try:
            ip = ipaddress.ip_address(part)
            if not (ip.is_loopback or ip.is_unspecified):
                found.add(str(ip))
        except Exception:
            pass
    # Active SSH peers via ss (best effort)
    try:
        r = _run(["ss", "-tn", "sport", "=", ":22"])
        for line in (r.get("stdout") or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            peer = parts[4]
            if ":" not in peer:
                continue
            # IPv4 host:port or [ipv6]:port
            if peer.startswith("["):
                host = peer[1:].split("]")[0]
            else:
                host = peer.rsplit(":", 1)[0]
            try:
                ip = ipaddress.ip_address(host)
                if not (ip.is_loopback or ip.is_unspecified):
                    found.add(str(ip))
            except Exception:
                pass
    except Exception:
        pass
    # Persist last-seen operators so a later cron block still respects them
    try:
        p = _data() / "operator_ips.json"
        prev = []
        if p.exists():
            prev = json.loads(p.read_text()).get("ips") or []
        merged = sorted(set(prev) | found)
        p.write_text(json.dumps({"ips": merged[-20:], "updated": _now()}, indent=2))
        for x in prev:
            found.add(x)
    except Exception:
        pass
    return sorted(found)


def is_operator_target(target: str) -> bool:
    try:
        kind, norm = _parse_target(target)
    except Exception:
        norm = (target or "").strip()
    ops = detect_operator_ips()
    if norm in ops:
        return True
    try:
        ip = ipaddress.ip_address(norm.split("/")[0])
        for o in ops:
            if ip == ipaddress.ip_address(o):
                return True
    except Exception:
        pass
    return False


def protect_operator(confirm: bool = False) -> dict:
    """Insert ACCEPT rules for current operator IPs (lockout guard)."""
    ops = detect_operator_ips()
    if not ops:
        return {"ok": True, "protected": [], "note": "no operator IP detected (local console?)"}
    if not confirm:
        return {"ok": True, "dry_run": True, "would_protect": ops, "hint": "pass --confirm to apply ACCEPT rules"}
    b = backend()
    ensure_backend_ready()
    results = []
    for ip in ops:
        if b == "nft":
            fam = "ip6" if ":" in ip else "ip"
            r = _run([
                "nft", "insert", "rule", "inet", "sentinel", "input",
                fam, "saddr", ip, "accept", "comment", "sentinel-operator",
            ])
        else:
            tool = "ip6tables" if ":" in ip else "iptables"
            if tool == "ip6tables" and not shutil.which("ip6tables"):
                results.append({"ip": ip, "ok": False, "error": "ip6tables not found"})
                continue
            r = _run([tool, "-I", "INPUT", "1", "-s", ip, "-j", "ACCEPT", "-m", "comment", "--comment", "sentinel-operator"])
        results.append({"ip": ip, "ok": r.get("ok", False), "detail": r})
    _audit("protect_operator", {"ips": ops, "results": results}, ok=all(x.get("ok") for x in results) if results else True)
    _case_event("FIREWALL_OPERATOR_PROTECT", {"ips": ops})
    return {"ok": True, "protected": ops, "results": results, "applied": True}


def _case_event(title: str, detail: dict) -> None:
    """Best-effort: attach firewall actions to the case system for evidence packs."""
    try:
        from modules.cases import create_case, add_note
        c = create_case(title=title, severity="INFO", source="firewall", details=detail)
        if isinstance(c, dict) and c.get("id"):
            add_note(c["id"], f"firewall: {title} {json.dumps(detail)[:300]}")
    except Exception:
        try:
            from modules.cases import open_case
            open_case(title, detail)
        except Exception:
            pass


def ensure_backend_ready() -> dict:
    b = backend()
    if b == "none":
        return {"ok": False, "error": "neither nft nor iptables found"}
    if b == "nft":
        _run(["nft", "add", "table", "inet", "sentinel"])
        r = _run(
            [
                "nft", "add", "chain", "inet", "sentinel", "input",
                "{", "type", "filter", "hook", "input", "priority", "-5", ";",
                "policy", "accept", ";", "}",
            ]
        )
        ok = r["ok"] or "exists" in (r.get("stderr") or "").lower() or r["code"] in (0, 1)
        return {"ok": ok, "backend": b, "detail": r}
    return {"ok": True, "backend": b}


def status() -> dict:
    b = backend()
    blocks = _load_blocks()
    out: dict[str, Any] = {
        "ok": True,
        "version": VERSION,
        "backend": b,
        "enabled": blocks.get("enabled", True),
        "profile": blocks.get("profile") or "default",
        "managed_ips": len(blocks.get("ips") or []),
        "managed_cidrs": len(blocks.get("cidrs") or []),
        "managed_port_allows": len(blocks.get("ports_allow") or []),
        "managed_port_denies": len(blocks.get("ports_deny") or []),
        "max_blocks": _max_blocks(),
        "note": "Host firewall control — not a perimeter network firewall",
        "dry_run_default": True,
        "operator_ips": detect_operator_ips(),
        "lockout_guard": True,
        "ipv6": True,
    }
    if b == "none":
        out["ok"] = False
        out["error"] = "neither nft nor iptables found"
        return out
    if b == "nft":
        r = _run(["nft", "list", "table", "inet", "sentinel"])
        if not r["ok"]:
            r = _run(["nft", "list", "ruleset"])
        out["ruleset_preview"] = "\n".join((r.get("stdout") or "").splitlines()[:50])
        out["ruleset_ok"] = bool(r.get("stdout"))
    else:
        r = _run(["iptables", "-L", "INPUT", "-n", "-v", "--line-numbers"])
        out["ruleset_preview"] = "\n".join((r.get("stdout") or "").splitlines()[:50])
        out["ruleset_ok"] = r["ok"]
    return out


def block_ip(target: str, confirm: bool = False, reason: str = "", source: str = "cli") -> dict:
    try:
        kind, norm = _parse_target(target)
    except ValueError as e:
        return {"ok": False, "error": str(e), "target": target}

    b = backend()
    if not confirm:
        _audit("block_dry_run", {"target": norm, "kind": kind, "reason": reason, "backend": b, "source": source})
        return {
            "ok": True,
            "dry_run": True,
            "would": f"block {norm} on INPUT",
            "kind": kind,
            "backend": b,
            "hint": "pass --confirm to apply",
        }
    if b == "none":
        return {"ok": False, "error": "no firewall backend"}

    data = _load_blocks()
    if not data.get("enabled", True):
        return {"ok": False, "error": "firewall managed plane disabled — enable first"}

    total = len(data.get("ips") or []) + len(data.get("cidrs") or [])
    already = norm in (data.get("ips") or []) or norm in (data.get("cidrs") or [])
    if not already and total >= _max_blocks():
        return {"ok": False, "error": f"max_blocks {_max_blocks()} reached"}

    ready = ensure_backend_ready()
    if not ready.get("ok"):
        return {"ok": False, "error": "backend not ready", "detail": ready}

    # Lockout guard — never block the operator's current/recent SSH IPs
    if is_operator_target(norm):
        _audit("block_refused_lockout", {"target": norm, "operator_ips": detect_operator_ips(), "source": source}, ok=False)
        return {
            "ok": False,
            "error": "lockout_guard: refused to block operator IP",
            "target": norm,
            "operator_ips": detect_operator_ips(),
            "hint": "This is your current SSH session IP — blocking it would lock you out",
        }

    if b == "nft":
        fam = "ip6" if ":" in norm.split("/")[0] else "ip"
        r = _run(["nft", "insert", "rule", "inet", "sentinel", "input", fam, "saddr", norm, "drop", "comment", "sentinel"])
    else:
        is_v6 = ":" in norm.split("/")[0]
        tool = "ip6tables" if is_v6 else "iptables"
        if is_v6 and not shutil.which("ip6tables"):
            return {"ok": False, "error": "ip6tables not found — cannot block IPv6 target", "target": norm}
        r = _run([tool, "-I", "INPUT", "1", "-s", norm, "-j", "DROP", "-m", "comment", "--comment", "sentinel-block"])

    if kind == "cidr":
        if norm not in data["cidrs"]:
            data["cidrs"].append(norm)
    else:
        if norm not in data["ips"]:
            data["ips"].append(norm)
    _save_blocks(data)
    _audit("block", {"target": norm, "kind": kind, "reason": reason, "backend": b, "source": source, "result": r}, ok=r.get("ok", False))
    _case_event("FIREWALL_BLOCK", {"target": norm, "reason": reason, "source": source, "ok": r.get("ok")})
    return {"ok": r.get("ok", False), "target": norm, "kind": kind, "backend": b, "applied": True, "detail": r, "source": source}


def unblock_ip(target: str, confirm: bool = False) -> dict:
    try:
        kind, norm = _parse_target(target)
    except ValueError:
        norm = (target or "").strip()
        kind = "ip"
        if not norm:
            return {"ok": False, "error": "empty target"}

    if not confirm:
        return {"ok": True, "dry_run": True, "would": f"unblock {norm}"}

    b = backend()
    results = []
    if b == "iptables":
        is_v6 = ":" in norm.split("/")[0]
        tool = "ip6tables" if is_v6 else "iptables"
        if is_v6 and not shutil.which("ip6tables"):
            return {"ok": False, "error": "ip6tables not found", "target": norm}
        for _ in range(8):
            r = _run([tool, "-D", "INPUT", "-s", norm, "-j", "DROP"])
            results.append(r)
            if not r["ok"]:
                break
    elif b == "nft":
        results.append({"ok": True, "note": "removed from managed list"})

    data = _load_blocks()
    data["ips"] = [x for x in data.get("ips") or [] if x != norm]
    data["cidrs"] = [x for x in data.get("cidrs") or [] if x != norm]
    _save_blocks(data)
    _audit("unblock", {"target": norm, "kind": kind, "results": results})
    return {"ok": True, "target": norm, "applied": True, "backend": b}


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
    ensure_backend_ready()
    if b == "iptables":
        r = _run(["iptables", "-I", "INPUT", "1", "-p", proto, "--dport", str(port), "-j", "ACCEPT", "-m", "comment", "--comment", "sentinel-allow-port"])
    else:
        r = _run(["nft", "insert", "rule", "inet", "sentinel", "input", proto, "dport", str(port), "accept", "comment", "sentinel"])
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
    if port < 1 or port > 65535:
        return {"ok": False, "error": "port out of range"}
    proto = (proto or "tcp").lower()
    if not confirm:
        return {"ok": True, "dry_run": True, "would": f"deny {proto}/{port} INPUT", "backend": backend()}
    b = backend()
    if b == "none":
        return {"ok": False, "error": "no firewall backend"}
    ensure_backend_ready()
    if b == "iptables":
        r = _run(["iptables", "-I", "INPUT", "1", "-p", proto, "--dport", str(port), "-j", "DROP", "-m", "comment", "--comment", "sentinel-deny-port"])
    else:
        r = _run(["nft", "insert", "rule", "inet", "sentinel", "input", proto, "dport", str(port), "drop", "comment", "sentinel"])
    data = _load_blocks()
    key = f"{proto}/{port}"
    if key not in (data.get("ports_deny") or []):
        data.setdefault("ports_deny", []).append(key)
        _save_blocks(data)
    _audit("deny_port", {"port": port, "proto": proto, "result": r}, ok=r.get("ok", False))
    return {"ok": r.get("ok", False), "port": port, "proto": proto, "applied": True}


PROFILES = {
    "default": {"description": "Track managed blocks only; no policy change", "actions": []},
    "hardening": {
        "description": "Deny common risky inbound Windows/SMB/RDP ports if not needed",
        "deny_ports": [(135, "tcp"), (139, "tcp"), (445, "tcp"), (3389, "tcp")],
    },
    "web_server": {"description": "Allow HTTP/HTTPS inbound", "allow_ports": [(80, "tcp"), (443, "tcp")]},
    "ssh_only": {"description": "Allow SSH 22/tcp — ensure console access first", "allow_ports": [(22, "tcp")]},
    "lab_lockdown": {
        "description": "Lab: deny SMB/RDP/RPC + allow SSH",
        "deny_ports": [(135, "tcp"), (139, "tcp"), (445, "tcp"), (3389, "tcp")],
        "allow_ports": [(22, "tcp")],
    },
}


def list_profiles() -> dict:
    return {"ok": True, "profiles": PROFILES}


def apply_profile(name: str, confirm: bool = False) -> dict:
    name = (name or "").strip().lower()
    if name not in PROFILES:
        return {"ok": False, "error": "unknown profile", "available": list(PROFILES)}
    prof = PROFILES[name]
    if not confirm:
        return {"ok": True, "dry_run": True, "profile": name, "would_apply": prof, "would_protect_operator": detect_operator_ips()}
    # Lockout guard before any deny rules
    protect_operator(confirm=True)
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


def apply_managed(confirm: bool = False) -> dict:
    data = _load_blocks()
    if not confirm:
        return {
            "ok": True,
            "dry_run": True,
            "would_apply_ips": list(data.get("ips") or []),
            "would_apply_cidrs": list(data.get("cidrs") or []),
            "ports_allow": list(data.get("ports_allow") or []),
            "ports_deny": list(data.get("ports_deny") or []),
        }
    if not data.get("enabled", True):
        return {"ok": False, "error": "managed plane disabled"}
    ensure_backend_ready()
    protect_operator(confirm=True)
    results = []
    for ip in list(data.get("ips") or []):
        results.append(block_ip(ip, confirm=True, reason="apply_managed", source="apply_managed"))
    for cidr in list(data.get("cidrs") or []):
        results.append(block_ip(cidr, confirm=True, reason="apply_managed", source="apply_managed"))
    for key in list(data.get("ports_allow") or []):
        try:
            proto, port_s = key.split("/")
            results.append(allow_port(int(port_s), proto, confirm=True))
        except Exception as e:
            results.append({"ok": False, "error": str(e), "key": key})
    for key in list(data.get("ports_deny") or []):
        try:
            proto, port_s = key.split("/")
            results.append(deny_port(int(port_s), proto, confirm=True))
        except Exception as e:
            results.append({"ok": False, "error": str(e), "key": key})
    _audit("apply_managed", {"count": len(results)})
    return {"ok": True, "applied": True, "results_count": len(results)}


def set_enabled(enabled: bool) -> dict:
    data = _load_blocks()
    data["enabled"] = bool(enabled)
    _save_blocks(data)
    _audit("set_enabled", {"enabled": bool(enabled)})
    return {"ok": True, "enabled": bool(enabled)}


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
    meta = _data() / f"managed_backup_{ts}.json"
    meta.write_text(json.dumps(_load_blocks(), indent=2))
    _audit("backup_rules", {"path": str(path), "meta": str(meta), "backend": b})
    return {"ok": True, "path": str(path), "meta": str(meta), "backend": b, "bytes": path.stat().st_size}


def list_managed() -> dict:
    return {"ok": True, **_load_blocks()}


def audit_tail(n: int = 30) -> dict:
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
    """Health check for host firewall plane."""
    st = status()
    issues = []
    if st.get("backend") == "none":
        issues.append({"severity": "high", "issue": "No nft/iptables backend on host"})
    elif not st.get("ruleset_ok"):
        issues.append({"severity": "medium", "issue": "Could not list ruleset (need root/capabilities?)"})
    if not st.get("enabled", True):
        issues.append({"severity": "medium", "issue": "Managed firewall plane disabled"})
    return {
        "ok": len([i for i in issues if i["severity"] == "high"]) == 0,
        "version": VERSION,
        "backend": st.get("backend"),
        "managed_ips": st.get("managed_ips"),
        "lockout_guard": True,
        "operator_ips": detect_operator_ips(),
        "ipv6": True,
        "issues": issues,
        "status": st,
    }


def cli(argv: list[str]) -> int:
    if not argv:
        print(json.dumps(status(), indent=2))
        return 0
    cmd = argv[0]
    rest = argv[1:]
    conf = "--confirm" in rest
    rest_f = [x for x in rest if x != "--confirm"]

    if cmd == "status":
        print(json.dumps(status(), indent=2))
    elif cmd == "block":
        target = rest_f[0] if rest_f else ""
        print(json.dumps(block_ip(target, confirm=conf), indent=2))
    elif cmd == "unblock":
        target = rest_f[0] if rest_f else ""
        print(json.dumps(unblock_ip(target, confirm=conf), indent=2))
    elif cmd == "allow-port":
        port = int(rest_f[0]) if rest_f else 0
        print(json.dumps(allow_port(port, confirm=conf), indent=2))
    elif cmd == "deny-port":
        port = int(rest_f[0]) if rest_f else 0
        print(json.dumps(deny_port(port, confirm=conf), indent=2))
    elif cmd == "profiles":
        print(json.dumps(list_profiles(), indent=2))
    elif cmd == "profile":
        name = rest_f[0] if rest_f else "default"
        print(json.dumps(apply_profile(name, confirm=conf), indent=2))
    elif cmd == "apply-managed":
        print(json.dumps(apply_managed(confirm=conf), indent=2))
    elif cmd in ("protect-operator", "lockout-guard"):
        print(json.dumps(protect_operator(confirm=conf), indent=2))
    elif cmd in ("operator-ips", "whoami-fw"):
        print(json.dumps({"ok": True, "operator_ips": detect_operator_ips()}, indent=2))
    elif cmd == "enable":
        print(json.dumps(set_enabled(True), indent=2))
    elif cmd == "disable":
        print(json.dumps(set_enabled(False), indent=2))
    elif cmd == "backup":
        print(json.dumps(backup_rules(), indent=2))
    elif cmd == "managed":
        print(json.dumps(list_managed(), indent=2))
    elif cmd == "audit":
        print(json.dumps(audit_tail(40), indent=2))
    elif cmd == "doctor":
        print(json.dumps(doctor(), indent=2))
    elif cmd == "ensure":
        print(json.dumps(ensure_backend_ready(), indent=2))
    else:
        print(f"unknown firewall command: {cmd}")
        print(
            "usage: status|block|unblock|allow-port|deny-port|profiles|profile|"
            "apply-managed|enable|disable|backup|managed|audit|doctor|ensure [--confirm]"
        )
        return 1
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(cli(sys.argv[1:]))
