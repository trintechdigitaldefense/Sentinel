#!/usr/bin/env python3
"""FEATURE 02 — MITRE ATT&CK tags for Sentinel detections."""
from __future__ import annotations
from typing import Optional

ATTACK_MAP = {
    "reverse_shell": [("T1059", "Command and Scripting Interpreter"), ("T1071", "Application Layer Protocol")],
    "suspicious_cmd": [("T1059", "Command and Scripting Interpreter")],
    "suspicious_process": [("T1059", "Command and Scripting Interpreter"), ("T1106", "Native API")],
    "malware_path": [("T1105", "Ingress Tool Transfer"), ("T1036", "Masquerading")],
    "canary": [("T1005", "Data from Local System"), ("T1552", "Unsecured Credentials")],
    "canary_triggered": [("T1005", "Data from Local System"), ("T1552.001", "Credentials In Files")],
    "ssh_bruteforce": [("T1110", "Brute Force"), ("T1110.001", "Password Guessing")],
    "ssh_failure": [("T1110", "Brute Force")],
    "fim": [("T1565", "Data Manipulation"), ("T1070", "Indicator Removal")],
    "integrity": [("T1565", "Data Manipulation"), ("T1070.004", "File Deletion")],
    "cron": [("T1053", "Scheduled Task/Job"), ("T1053.003", "Cron")],
    "systemd": [("T1543", "Create or Modify System Process"), ("T1543.002", "Systemd Service")],
    "persistence": [("T1547", "Boot or Logon Autostart Execution"), ("T1053", "Scheduled Task/Job")],
    "suid": [("T1548", "Abuse Elevation Control Mechanism"), ("T1548.001", "Setuid and Setgid")],
    "usb": [("T1091", "Replication Through Removable Media"), ("T1052", "Exfiltration Over Physical Medium")],
    "lateral": [("T1021", "Remote Services"), ("T1021.001", "Remote Desktop Protocol")],
    "rdp": [("T1021.001", "Remote Desktop Protocol")],
    "smb": [("T1021.002", "SMB/Windows Admin Shares")],
    "dns_exfil": [("T1071.004", "DNS"), ("T1048", "Exfiltration Over Alternative Protocol")],
    "new_device": [("T1200", "Hardware Additions"), ("T1046", "Network Service Discovery")],
    "deadman": [("T1489", "Service Stop")],
    "self_integrity": [("T1562", "Impair Defenses"), ("T1562.001", "Disable or Modify Tools")],
    "honey_auth": [("T1078", "Valid Accounts"), ("T1110", "Brute Force")],
    "outbound": [("T1041", "Exfiltration Over C2 Channel")],
}

def techniques_for(reason: str = "", alert_type: str = "", extra: Optional[str] = None) -> list:
    keys = []
    for part in (reason, alert_type, extra or ""):
        p = (part or "").strip().lower().replace(" ", "_").replace("-", "_")
        if p:
            keys.append(p)
            for k in ATTACK_MAP:
                if k in p or p in k:
                    keys.append(k)
    seen = set()
    out = []
    for k in keys:
        for tid, name in ATTACK_MAP.get(k, []):
            if tid not in seen:
                seen.add(tid)
                out.append({"id": tid, "name": name})
    return out

def tag_alert(alert: dict) -> dict:
    a = dict(alert)
    techs = techniques_for(
        str(a.get("reason") or ""),
        str(a.get("type") or a.get("alert_type") or ""),
        str(a.get("pattern") or a.get("matched") or ""),
    )
    a["techniques"] = techs
    a["technique_ids"] = [t["id"] for t in techs]
    return a

def summarize_techniques(alerts: list) -> list:
    seen = {}
    for al in alerts or []:
        tagged = tag_alert(al) if "techniques" not in al else al
        for t in tagged.get("techniques") or techniques_for(str(al.get("reason") or ""), str(al.get("type") or "")):
            seen[t["id"]] = t
    return sorted(seen.values(), key=lambda x: x["id"])

def print_map_sample() -> None:
    print("ATT&CK map entries:", len(ATTACK_MAP))
    for k, v in list(ATTACK_MAP.items())[:5]:
        print(f"  {k}: {v}")
