# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Sentinel nftables base ruleset + managed address sets.

Host INPUT filter (not perimeter):
  - invalid drop; established/related accept; loopback accept
  - limited ICMP
  - operator IP accept
  - @bad_hosts / @bad_hosts6 DROP (timeout)
  - high-risk port denies
  - optional SSH new-connection rate limit

Requires root + nft. Dry-run unless confirm=True.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sentinel.nftables_rules")

SET4 = "bad_hosts"
SET6 = "bad_hosts6"


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "ok": r.returncode == 0,
            "code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip(),
            "cmd": cmd,
        }
    except Exception as e:
        return {"ok": False, "code": -1, "stdout": "", "stderr": str(e), "cmd": cmd}


def available():
    return bool(shutil.which("nft"))


def is_root():
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def build_ruleset(
    ssh_port=22,
    rate_limit_ssh=True,
    operator_ips=None,
    deny_ports=None,
    policy_accept=True,
):
    ops = operator_ips or []
    deny_ports = deny_ports or [
        (135, "tcp"), (139, "tcp"), (445, "tcp"), (3389, "tcp"),
        (23, "tcp"), (21, "tcp"),
    ]
    op_rules = []
    for ip in ops:
        ip = (ip or "").strip()
        if not ip:
            continue
        if ":" in ip:
            op_rules.append("    ip6 saddr %s accept comment \"operator\"" % ip)
        else:
            op_rules.append("    ip saddr %s accept comment \"operator\"" % ip)

    deny_lines = []
    for port, proto in deny_ports:
        deny_lines.append(
            "    %s dport %d drop comment \"sentinel-deny-%d\"" % (proto, int(port), int(port))
        )

    ssh_rules = []
    if rate_limit_ssh and ssh_port:
        ssh_rules.append(
            "    tcp dport %d ct state new limit rate 10/minute burst 20 packets accept comment \"ssh-rate\"" % int(ssh_port)
        )
        ssh_rules.append(
            "    tcp dport %d ct state new drop comment \"ssh-rate-exceeded\"" % int(ssh_port)
        )

    policy = "accept" if policy_accept else "drop"
    op_block = "\n".join(op_rules) if op_rules else "    # (no operator IPs configured)"
    deny_block = "\n".join(deny_lines)
    ssh_block = "\n".join(ssh_rules) if ssh_rules else "    # ssh rate limit disabled"

    body = """# Sentinel host firewall — generated ruleset
# Safe default policy: %s

flush table inet sentinel

table inet sentinel {
  set bad_hosts {
    type ipv4_addr
    flags interval,timeout
    timeout 1h
  }

  set bad_hosts6 {
    type ipv6_addr
    flags interval,timeout
    timeout 1h
  }

  chain input {
    type filter hook input priority -5; policy %s;

    ct state invalid drop
    ct state established,related accept
    iif "lo" accept

    ip protocol icmp limit rate 5/second accept
    ip protocol icmp drop
    ip6 nexthdr icmpv6 limit rate 5/second accept

%s

    ip saddr @bad_hosts drop comment "sentinel-bad-hosts"
    ip6 saddr @bad_hosts6 drop comment "sentinel-bad-hosts6"

%s

%s
  }
}
""" % (policy, policy, op_block, deny_block, ssh_block)
    return body


def apply_base_ruleset(
    confirm=False,
    ssh_port=22,
    rate_limit_ssh=True,
    operator_ips=None,
    deny_ports=None,
):
    if not available():
        return {"ok": False, "error": "nft not found — apt install nftables"}
    rules = build_ruleset(
        ssh_port=ssh_port,
        rate_limit_ssh=rate_limit_ssh,
        operator_ips=operator_ips,
        deny_ports=deny_ports,
    )
    if not confirm:
        return {
            "ok": True,
            "dry_run": True,
            "would": "apply base nftables ruleset",
            "preview_lines": len(rules.splitlines()),
            "preview": "\n".join(rules.splitlines()[:45]) + "\n...",
            "hint": "sudo python3 sentinel.py nft-apply --confirm",
        }
    if not is_root():
        return {"ok": False, "error": "root required — run with sudo"}

    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(rules)
        path = f.name
    try:
        r = _run(["nft", "-f", path])
        verify = _run(["nft", "list", "table", "inet", "sentinel"])
        return {
            "ok": bool(r.get("ok")),
            "applied": bool(r.get("ok")),
            "backend": "nft",
            "detail": r,
            "verify_ok": bool(verify.get("ok")),
            "verify_snippet": (verify.get("stdout") or "")[:600],
        }
    finally:
        try:
            Path(path).unlink(missing_ok=True)
        except Exception:
            pass


def ensure_table():
    """Create table/sets/chain if missing (lightweight)."""
    if not available() or not is_root():
        return {"ok": False, "error": "nft/root required"}
    if _run(["nft", "list", "table", "inet", "sentinel"]).get("ok"):
        return {"ok": True, "exists": True}
    return apply_base_ruleset(confirm=True)


def add_to_bad_hosts(ip, timeout_sec=3600):
    if not available():
        return {"ok": False, "error": "nft not found"}
    if not is_root():
        return {"ok": False, "error": "root required"}
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "empty ip"}
    prep = ensure_table()
    if not prep.get("ok") and not prep.get("exists"):
        # still try add
        pass
    timeout = max(60, int(timeout_sec or 3600))
    set_name = SET6 if ":" in ip else SET4
    # Prefer element with timeout
    r = _run(["nft", "add", "element", "inet", "sentinel", set_name, "{", "%s timeout %ds" % (ip, timeout), "}"])
    if not r.get("ok"):
        r = _run(["nft", "add", "element", "inet", "sentinel", set_name, "{", ip, "}"])
    # Fallback: classic drop rule insert
    if not r.get("ok"):
        fam = "ip6" if ":" in ip else "ip"
        r = _run(["nft", "insert", "rule", "inet", "sentinel", "input", fam, "saddr", ip, "drop", "comment", "sentinel-block"])
    return {"ok": bool(r.get("ok")), "ip": ip, "timeout_sec": timeout, "detail": r, "method": "nft_set_or_rule"}


def remove_from_bad_hosts(ip):
    if not available() or not is_root():
        return {"ok": False, "error": "nft/root required"}
    ip = (ip or "").strip()
    set_name = SET6 if ":" in ip else SET4
    r = _run(["nft", "delete", "element", "inet", "sentinel", set_name, "{", ip, "}"])
    return {"ok": bool(r.get("ok")) or "No such" in (r.get("stderr") or ""), "ip": ip, "detail": r}


def list_ruleset():
    if not available():
        return {"ok": False, "error": "nft not found"}
    r = _run(["nft", "list", "table", "inet", "sentinel"])
    if not r.get("ok"):
        r = _run(["nft", "list", "ruleset"])
    return {"ok": bool(r.get("ok")), "ruleset": r.get("stdout") or "", "detail": r}
