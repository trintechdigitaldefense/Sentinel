# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SSH / auth brute-force detection and host-firewall blocking.

Parses journald + auth logs (IPv4/IPv6), thresholds failures, and applies
blocks via modules.firewall (nft/iptables, lockout guard, audit).

Defaults are supervised:
  auto_block = False  → detect + alert candidates only
  auto_block = True   → progressive host firewall DROP
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger("sentinel.brute_force")

# IPv4 or IPv6 after "from "
_IP_FROM = re.compile(
    r"from\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)",
    re.I,
)
_IP_RHOST = re.compile(
    r"rhost[=:](\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)",
    re.I,
)
_IP_GENERIC = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3})\b",
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
    "Failed keyboard-interactive",
    "error: maximum authentication attempts",
    "PAM 1 more authentication failure",
    "pam_unix(sshd:auth): authentication failure",
    "sshd: Failed",
    "Did not receive identification string",  # scan noise — count lightly via same bucket
    "Bad protocol version identification",
    "Unable to negotiate with",
    "Connection reset by",
    "Invalid user",
    "not allowed because none of user's groups",
)


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def blocklist_path() -> Path:
    return _data() / "iptables_blocklist.json"


def offense_path() -> Path:
    return _data() / "ssh_offense_counts.json"


def _load_blocklist() -> dict:
    p = blocklist_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception as e:
            log.debug("blocklist load: %s", e)
    return {"blocked": {}, "whitelist": [], "updated": None, "history": []}


def _save_blocklist(data: dict) -> None:
    data["updated"] = datetime.now(timezone.utc).isoformat()
    blocklist_path().write_text(json.dumps(data, indent=2))
    try:
        os.chmod(blocklist_path(), 0o600)
    except Exception as e:
        log.debug("blocklist chmod: %s", e)


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
    return dict((config or {}).get("ssh_blocking") or {})


def _window_hours(ssh: dict) -> int:
    # prefer explicit hours; else derive from time_window seconds
    if ssh.get("log_hours"):
        return max(1, int(ssh["log_hours"]))
    tw = int(ssh.get("time_window") or 600)
    return max(1, min(24, (tw + 3599) // 3600 * 2 or 2))  # at least 2h of logs


def _collect_auth_text(ssh: Optional[dict] = None) -> str:
    ssh = ssh or {}
    hours = _window_hours(ssh)
    max_lines = int(ssh.get("log_lines") or 1200)
    since = f"{hours} hours ago"
    chunks: list[str] = []
    for cmd in (
        ["journalctl", "-u", "ssh", "--since", since, "-n", str(max_lines), "--no-pager"],
        ["journalctl", "-u", "sshd", "--since", since, "-n", str(max_lines), "--no-pager"],
        ["journalctl", "-t", "sshd", "--since", since, "-n", str(max_lines // 2), "--no-pager"],
        ["journalctl", "-t", "ssh", "--since", since, "-n", str(max_lines // 2), "--no-pager"],
    ):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if r.stdout:
                chunks.append(r.stdout)
        except Exception as e:
            log.debug("journalctl: %s", e)

    for logp in ("/var/log/auth.log", "/var/log/secure", "/var/log/messages"):
        try:
            p = Path(logp)
            if not p.exists():
                continue
            data = p.read_bytes()
            if len(data) > 400_000:
                data = data[-400_000:]
            chunks.append(data.decode("utf-8", errors="ignore"))
        except Exception as e:
            log.debug("auth file %s: %s", logp, e)

    return "\n".join(chunks)


def _extract_ip(line: str) -> Optional[str]:
    m = _IP_FROM.search(line)
    if m:
        return m.group(1)
    m = _IP_RHOST.search(line)
    if m:
        return m.group(1)
    # last resort: only if line clearly sshd-related
    if "sshd" in line.lower() or "ssh" in line.lower():
        ips = _IP_GENERIC.findall(line)
        for ip in reversed(ips):
            if not ip.startswith("127.") and ip != "0.0.0.0":
                return ip
    return None


def parse_failures(text: str) -> dict[str, int]:
    """Return {ip: failure_count} from auth log text."""
    failures: dict[str, int] = {}
    for line in text.splitlines():
        if not any(m in line for m in _FAIL_MARKERS):
            continue
        ip = _extract_ip(line)
        if not ip:
            continue
        if ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            continue
        # normalize ipv4-mapped
        if ip.startswith("::ffff:"):
            ip = ip.split("::ffff:")[-1]
        failures[ip] = failures.get(ip, 0) + 1
    return failures


def _is_whitelisted(ip: str, ssh_cfg: dict, blocklist: dict) -> bool:
    wl = set(ssh_cfg.get("whitelist_ips") or []) | set(blocklist.get("whitelist") or [])
    if ip in wl:
        return True
    # CIDR-ish prefix match for simple "192.168.1." entries
    for entry in wl:
        if entry.endswith(".") and ip.startswith(entry):
            return True
        if "/" in str(entry):
            try:
                import ipaddress
                if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                    return True
            except Exception:
                pass
    try:
        from modules.firewall import is_operator_target, detect_operator_ips
        if is_operator_target(ip):
            return True
        if ip in detect_operator_ips():
            return True
    except Exception as e:
        log.debug("operator check: %s", e)
    return False


def expire_blocks(logger=None) -> dict:
    """Unblock IPs whose block_until has passed."""
    bl = _load_blocklist()
    now = datetime.now()
    expired = []
    still = {}
    for ip, meta in (bl.get("blocked") or {}).items():
        until = meta.get("block_until")
        try:
            bt = datetime.fromisoformat(str(until).replace("Z", "+00:00").replace("+00:00", ""))
            # naive compare
            if getattr(bt, "tzinfo", None):
                bt = bt.replace(tzinfo=None)
            if now >= bt:
                expired.append(ip)
                try:
                    from modules.firewall import unblock_ip
                    unblock_ip(ip, confirm=True)
                except Exception:
                    subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=5,
                    )
                continue
        except Exception as e:
            log.debug("expire parse %s: %s", ip, e)
        still[ip] = meta
    bl["blocked"] = still
    _save_blocklist(bl)
    if logger and expired:
        logger.info("Expired %d SSH blocks: %s", len(expired), ", ".join(expired[:8]))
    return {"ok": True, "expired": expired, "active": len(still)}


def progressive_duration(ip: str, base: int, ssh: dict) -> int:
    """Scale ban duration by repeat offenses for this IP. Cap at max_duration."""
    base = max(60, int(base or 1800))
    max_d = int(ssh.get("max_block_duration") or 86400)
    mult = float(ssh.get("repeat_multiplier") or 2.0)
    store = offense_path()
    counts: dict[str, Any] = {}
    if store.exists():
        try:
            counts = json.loads(store.read_text())
        except Exception as e:
            log.debug("offense load: %s", e)
            counts = {}
    n = int(counts.get(ip, 0)) + 1
    counts[ip] = n
    try:
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(json.dumps(counts, indent=2))
        try:
            os.chmod(store, 0o600)
        except Exception as e:
            log.debug("offense chmod: %s", e)
    except Exception as e:
        log.debug("offense save: %s", e)
    dur = int(base * (mult ** max(0, n - 1)))
    return min(dur, max_d)


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

    now = datetime.now()
    if ip in (bl.get("blocked") or {}):
        try:
            bt = datetime.fromisoformat(str(bl["blocked"][ip].get("block_until", "")).replace("Z", ""))
            if getattr(bt, "tzinfo", None):
                bt = bt.replace(tzinfo=None)
            if now < bt:
                return {"ok": True, "already_blocked": True, "ip": ip, "until": bt.isoformat()}
        except Exception as e:
            log.debug("already-blocked parse: %s", e)

    fw_result: dict[str, Any] = {}
    applied = False
    try:
        from modules.firewall import block_ip, protect_operator, ensure_backend_ready, drop_capabilities
        caps = drop_capabilities()
        if not caps.get("real_drop"):
            fw_result = {
                "ok": False,
                "error": "real DROP unavailable",
                "capabilities": caps,
                "hints": caps.get("hints"),
            }
            applied = False
        else:
            prep = ensure_backend_ready()
            if not prep.get("ok"):
                fw_result = {"ok": False, "error": "backend prepare failed", "prepare": prep}
                applied = False
            else:
                try:
                    protect_operator(confirm=True)
                except Exception as e:
                    log.debug("protect_operator: %s", e)
                fw_result = block_ip(ip, confirm=True, reason=reason, source=source)
                applied = bool(fw_result.get("ok")) and bool(fw_result.get("applied") or fw_result.get("real_drop") or fw_result.get("verified")) and not fw_result.get("dry_run")
    except Exception as e:
        fw_result = {"ok": False, "error": str(e)}

    until = (now + timedelta(seconds=int(duration))).isoformat()
    bl.setdefault("blocked", {})[ip] = {
        "reason": reason,
        "failures": failures,
        "blocked_at": now.isoformat(),
        "block_until": until,
        "duration_sec": int(duration),
        "firewall": {k: fw_result.get(k) for k in ("ok", "backend", "dry_run", "error", "applied")},
        "source": source,
    }
    hist = list(bl.get("history") or [])
    hist.append({"ip": ip, "at": now.isoformat(), "reason": reason, "duration": duration})
    bl["history"] = hist[-50:]
    _save_blocklist(bl)

    if send_alert:
        try:
            send_alert(
                "SSH_IP_BLOCKED",
                {"ip": ip, "reason": reason, "failures": failures, "until": until, "applied": applied},
            )
        except Exception as e:
            log.debug("alert: %s", e)

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
        "until": until,
        "recorded": True,
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

    text = _collect_auth_text(ssh)
    failures = parse_failures(text)
    max_failures = int(ssh.get("max_failures") or 5)
    duration = int(ssh.get("block_duration") or 1800)
    auto = bool(ssh.get("auto_block", False))
    alert_candidates = ssh.get("alert_on_candidate", True)
    alert_on_block = ssh.get("alert_on_block", True)

    blocked = []
    candidates = []
    top = sorted(failures.items(), key=lambda x: -x[1])[:20]

    for ip, count in sorted(failures.items(), key=lambda x: -x[1]):
        if count < max_failures:
            continue
        if _is_whitelisted(ip, ssh, _load_blocklist()):
            continue
        entry = {"ip": ip, "failures": count, "threshold": max_failures}
        candidates.append(entry)

        if send_alert and alert_candidates and not auto:
            try:
                send_alert(
                    "SSH_BRUTE_CANDIDATE",
                    {"ip": ip, "failures": count, "threshold": max_failures, "auto_block": False},
                )
            except Exception as e:
                log.debug("candidate alert: %s", e)

        if not auto:
            continue

        ban_for = progressive_duration(ip, duration, ssh)
        r = apply_block(
            ip,
            reason=f"SSH brute force: {count} failures (ban {ban_for}s)",
            failures=count,
            duration=ban_for,
            send_alert=send_alert if alert_on_block else None,
            logger=logger,
        )
        entry["block"] = r
        if r.get("applied") or r.get("already_blocked") or r.get("recorded"):
            blocked.append(r)

    result = {
        "ok": True,
        "failures_tracked": len(failures),
        "top_offenders": [{"ip": i, "failures": c} for i, c in top[:10]],
        "candidates": candidates,
        "blocked": blocked,
        "blocked_count": len(blocked),
        "max_failures": max_failures,
        "auto_block": auto,
        "log_chars": len(text),
    }
    # persist last scan for dashboard
    try:
        (_data() / "ssh_last_scan.json").write_text(
            json.dumps({**result, "ts": datetime.now().isoformat()}, indent=2, default=str)
        )
    except Exception as e:
        log.debug("last scan save: %s", e)
    return result


def status() -> dict:
    bl = _load_blocklist()
    ssh = _cfg_ssh()
    last = {}
    lp = _data() / "ssh_last_scan.json"
    if lp.exists():
        try:
            last = json.loads(lp.read_text())
        except Exception:
            last = {}
    offenses = {}
    if offense_path().exists():
        try:
            offenses = json.loads(offense_path().read_text())
        except Exception:
            offenses = {}
    return {
        "ok": True,
        "active_blocks": len(bl.get("blocked") or {}),
        "whitelist": bl.get("whitelist") or [],
        "blocked": bl.get("blocked") or {},
        "path": str(blocklist_path()),
        "config": {
            "active": ssh.get("active", True),
            "auto_block": ssh.get("auto_block", False),
            "max_failures": ssh.get("max_failures", 5),
            "block_duration": ssh.get("block_duration", 1800),
            "max_block_duration": ssh.get("max_block_duration", 86400),
            "repeat_multiplier": ssh.get("repeat_multiplier", 2.0),
        },
        "offense_counts": offenses,
        "last_scan": {
            "ts": last.get("ts"),
            "failures_tracked": last.get("failures_tracked"),
            "candidates": last.get("candidates"),
            "blocked_count": last.get("blocked_count"),
            "auto_block": last.get("auto_block"),
            "top_offenders": last.get("top_offenders"),
        },
        "history_recent": (bl.get("history") or [])[-10:],
    }


def whitelist_add(ip: str) -> dict:
    bl = _load_blocklist()
    wl = list(bl.get("whitelist") or [])
    if ip not in wl:
        wl.append(ip)
    bl["whitelist"] = wl
    # remove from blocked if present
    if ip in (bl.get("blocked") or {}):
        del bl["blocked"][ip]
        try:
            from modules.firewall import unblock_ip
            unblock_ip(ip, confirm=True)
        except Exception as e:
            log.debug("whitelist unblock: %s", e)
    _save_blocklist(bl)
    return {"ok": True, "whitelist": wl}


def unblock(ip: str) -> dict:
    bl = _load_blocklist()
    bl.setdefault("blocked", {}).pop(ip, None)
    _save_blocklist(bl)
    fw = {}
    try:
        from modules.firewall import unblock_ip
        fw = unblock_ip(ip, confirm=True)
    except Exception as e:
        fw = {"error": str(e)}
    return {"ok": True, "ip": ip, "firewall": fw}
