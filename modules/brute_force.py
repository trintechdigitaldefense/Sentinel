# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SSH / auth brute-force detection and host-firewall blocking.

Parses journald + auth logs (IPv4/IPv6), thresholds failures, and applies
blocks via modules.firewall (nft/iptables, lockout guard, audit, cases).

Does not use shell-out iptables strings — all applies go through the
firewall control plane.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

# IPv4 or IPv6 (simplified) after "from "
_IP_FROM = re.compile(
    r"from\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)",
    re.I,
)
_FAIL_MARKERS = (
    "Failed password",
    "authentication failure",
    "Invalid user",
    "Failed none",
    "Connection closed by authenticating user",
    "Disconnected from authenticating user",
    "maximum authentication attempts exceeded",
    "Failed publickey",
)


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def blocklist_path() -> Path:
    return _data() / "iptables_blocklist.json"


def _load_blocklist() -> dict:
    p = blocklist_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {"blocked": {}, "whitelist": [], "updated": None}


def _save_blocklist(data: dict) -> None:
    data["updated"] = datetime.now(timezone.utc).isoformat()
    blocklist_path().write_text(json.dumps(data, indent=2))


def _cfg_ssh(config: Optional[dict] = None) -> dict:
    if config is None:
        p = _home() / "config.json"
        if p.exists():
            try:
                config = json.loads(p.read_text())
            except Exception:
                config = {}
        else:
            config = {}
    return (config or {}).get("ssh_blocking") or {}


def _collect_auth_text() -> str:
    chunks = []
    for cmd in (
        ["journalctl", "-u", "ssh", "--since", "2 hours ago", "-n", "800", "--no-pager"],
        ["journalctl", "-u", "sshd", "--since", "2 hours ago", "-n", "800", "--no-pager"],
        ["journalctl", "-t", "sshd", "--since", "2 hours ago", "-n", "500", "--no-pager"],
    ):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if r.stdout:
                chunks.append(r.stdout)
        except Exception:
            pass
    for logp in ("/var/log/auth.log", "/var/log/secure"):
        try:
            p = Path(logp)
            if p.exists():
                # last ~200KB
                data = p.read_bytes()
                if len(data) > 200_000:
                    data = data[-200_000:]
                chunks.append(data.decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return "\n".join(chunks)


def parse_failures(text: str) -> dict[str, int]:
    """Return {ip: failure_count} from auth log text."""
    failures: dict[str, int] = {}
    for line in text.splitlines():
        if not any(m in line for m in _FAIL_MARKERS):
            continue
        m = _IP_FROM.search(line)
        if not m:
            # rhost=1.2.3.4 style (pam)
            m2 = re.search(r"rhost=(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)", line, re.I)
            if not m2:
                continue
            ip = m2.group(1)
        else:
            ip = m.group(1)
        # skip empties / obvious junk
        if ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            continue
        failures[ip] = failures.get(ip, 0) + 1
    return failures


def _is_whitelisted(ip: str, ssh_cfg: dict, blocklist: dict) -> bool:
    wl = set(ssh_cfg.get("whitelist_ips") or []) | set(blocklist.get("whitelist") or [])
    if ip in wl:
        return True
    try:
        from modules.firewall import is_operator_target, detect_operator_ips
        if is_operator_target(ip):
            return True
        if ip in detect_operator_ips():
            return True
    except Exception:
        pass
    return False


def expire_blocks(logger=None) -> dict:
    """Unblock IPs whose block_until has passed (via firewall plane when possible)."""
    bl = _load_blocklist()
    now = datetime.now()
    expired = []
    still = {}
    for ip, meta in (bl.get("blocked") or {}).items():
        until = meta.get("block_until")
        try:
            bt = datetime.fromisoformat(str(until).replace("Z", ""))
            if now >= bt:
                expired.append(ip)
                try:
                    from modules.firewall import unblock_ip
                    unblock_ip(ip, confirm=True)
                except Exception:
                    # best-effort raw delete
                    subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=5,
                    )
                continue
        except Exception:
            pass
        still[ip] = meta
    bl["blocked"] = still
    _save_blocklist(bl)
    if logger and expired:
        logger.info("Expired %d SSH blocks: %s", len(expired), ", ".join(expired[:8]))
    return {"ok": True, "expired": expired, "active": len(still)}


def apply_block(
    ip: str,
    reason: str,
    failures: int,
    duration: int,
    send_alert: Optional[Callable] = None,
    logger=None,
    source: str = "ssh_bruteforce",
) -> dict:
    """Block via firewall control plane + record in Sentinel blocklist."""
    ssh_cfg = _cfg_ssh()
    bl = _load_blocklist()
    if _is_whitelisted(ip, ssh_cfg, bl):
        return {"ok": False, "error": "whitelisted_or_operator", "ip": ip}

    # Already blocked and not expired?
    now = datetime.now()
    if ip in (bl.get("blocked") or {}):
        try:
            bt = datetime.fromisoformat(str(bl["blocked"][ip].get("block_until", "")).replace("Z", ""))
            if now < bt:
                return {"ok": True, "already_blocked": True, "ip": ip, "until": bt.isoformat()}
        except Exception:
            pass

    fw_result: dict[str, Any] = {}
    try:
        from modules.firewall import block_ip, protect_operator
        # Ensure operator stay-alive before applying drops
        try:
            protect_operator(confirm=True)
        except Exception:
            pass
        fw_result = block_ip(ip, confirm=True, reason=reason, source=source)
    except Exception as e:
        fw_result = {"ok": False, "error": str(e)}

    # Record regardless of backend availability (audit trail for pilot hosts without nft)
    bl.setdefault("blocked", {})[ip] = {
        "reason": reason,
        "failures": failures,
        "blocked_at": now.isoformat(),
        "block_until": (now + timedelta(seconds=duration)).isoformat(),
        "source": source,
        "firewall": {
            "ok": fw_result.get("ok"),
            "backend": fw_result.get("backend"),
            "error": fw_result.get("error"),
        },
    }
    _save_blocklist(bl)

    applied = bool(fw_result.get("ok")) and not fw_result.get("dry_run")
    if send_alert:
        try:
            send_alert(
                "IP_BLOCKED",
                {
                    "ip": ip,
                    "failures": failures,
                    "reason": reason,
                    "duration": duration,
                    "firewall_ok": applied,
                    "backend": fw_result.get("backend"),
                },
            )
        except Exception:
            pass
    if logger:
        if applied:
            logger.warning("IP BLOCKED %s (%s) via firewall plane", ip, reason)
        elif fw_result.get("error") == "lockout_guard: refused to block operator IP":
            logger.warning("Lockout guard refused block of operator IP %s", ip)
        else:
            logger.warning(
                "SSH threshold hit for %s (%s) — firewall apply: %s",
                ip, reason, fw_result.get("error") or fw_result,
            )

    return {
        "ok": True,
        "ip": ip,
        "applied": applied,
        "firewall": fw_result,
        "until": bl["blocked"][ip]["block_until"],
    }


def check(
    config: Optional[dict] = None,
    send_alert: Optional[Callable] = None,
    logger=None,
) -> dict:
    """Main hunt-loop entry: parse failures, expire old blocks, apply new ones."""
    ssh = _cfg_ssh(config)
    if not ssh.get("active", True):
        return {"ok": True, "skipped": True, "reason": "ssh_blocking inactive"}

    expire_blocks(logger=logger)

    text = _collect_auth_text()
    failures = parse_failures(text)
    max_failures = int(ssh.get("max_failures") or 5)
    duration = int(ssh.get("block_duration") or 1800)
    auto = ssh.get("auto_block", True)

    blocked = []
    candidates = []
    for ip, count in sorted(failures.items(), key=lambda x: -x[1]):
        if count < max_failures:
            continue
        candidates.append({"ip": ip, "failures": count})
        if not auto:
            continue
        r = apply_block(
            ip,
            reason=f"SSH brute force: {count} failures",
            failures=count,
            duration=duration,
            send_alert=send_alert if ssh.get("alert_on_block", True) else None,
            logger=logger,
        )
        if r.get("applied") or r.get("already_blocked"):
            blocked.append(r)

    return {
        "ok": True,
        "failures_tracked": len(failures),
        "candidates": candidates,
        "blocked": blocked,
        "blocked_count": len(blocked),
        "max_failures": max_failures,
        "auto_block": auto,
    }


def status() -> dict:
    bl = _load_blocklist()
    return {
        "ok": True,
        "active_blocks": len(bl.get("blocked") or {}),
        "whitelist": bl.get("whitelist") or [],
        "blocked": bl.get("blocked") or {},
        "path": str(blocklist_path()),
    }


def whitelist_add(ip: str) -> dict:
    bl = _load_blocklist()
    wl = list(bl.get("whitelist") or [])
    if ip not in wl:
        wl.append(ip)
    bl["whitelist"] = wl
    _save_blocklist(bl)
    return {"ok": True, "whitelist": wl}
