# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL config schema + validation (feature 3).

Uses dataclasses + manual checks so pydantic is optional.
"""
from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def config_path() -> Path:
    return _home() / "config.json"


@dataclass
class WhatsAppCfg:
    enabled: bool = False
    phone: str = ""
    apikey: str = ""


@dataclass
class EmailCfg:
    enabled: bool = False
    smtp_server: str = ""
    smtp_port: int = 587
    from_email: str = ""
    to_emails: list = field(default_factory=list)
    username: str = ""
    password: str = ""
    use_tls: bool = True


@dataclass
class WebhookCfg:
    enabled: bool = False
    url: str = ""
    headers: dict = field(default_factory=dict)


@dataclass
class SyslogCfg:
    enabled: bool = False
    address: str = "127.0.0.1"
    port: int = 514


@dataclass
class QuietHoursCfg:
    enabled: bool = False
    start: str = "22:00"
    end: str = "07:00"


@dataclass
class AlertingCfg:
    whatsapp: WhatsAppCfg = field(default_factory=WhatsAppCfg)
    email: EmailCfg = field(default_factory=EmailCfg)
    webhook: WebhookCfg = field(default_factory=WebhookCfg)
    syslog: SyslogCfg = field(default_factory=SyslogCfg)
    quiet_hours: QuietHoursCfg = field(default_factory=QuietHoursCfg)
    dedup_minutes: int = 15


@dataclass
class ResponseCfg:
    enabled: bool = False
    kill_process: bool = False
    block_ip: bool = False
    disable_user: bool = False


@dataclass
class ThreatIntelCfg:
    enabled: bool = False
    abuseipdb_key: str = ""
    otx_key: str = ""
    cache_hours: int = 24


@dataclass
class DashboardCfg:
    port: int = 8792
    bind: str = "127.0.0.1"
    username: str = "admin"
    password: str = ""
    allow_control: bool = True
    token: str = ""


@dataclass
class CentralCfg:
    enabled: bool = False
    server_url: str = ""
    api_key: str = ""
    heartbeat_seconds: int = 300


@dataclass
class LoggingCfg:
    level: str = "INFO"
    json_files: bool = True
    retention_days: int = 30


@dataclass
class NetworkCfg:
    subnets: list = field(default_factory=list)
    auto_detect: bool = True


@dataclass
class AgentCfg:
    shared_token: str = ""
    mode: str = "standalone"


@dataclass
class SentinelConfig:
    version: str = "3.0.0"
    client_name: str = "Client"
    network: NetworkCfg = field(default_factory=NetworkCfg)
    alerting: AlertingCfg = field(default_factory=AlertingCfg)
    response: ResponseCfg = field(default_factory=ResponseCfg)
    threat_intel: ThreatIntelCfg = field(default_factory=ThreatIntelCfg)
    dashboard: DashboardCfg = field(default_factory=DashboardCfg)
    central: CentralCfg = field(default_factory=CentralCfg)
    logging: LoggingCfg = field(default_factory=LoggingCfg)
    agent: AgentCfg = field(default_factory=AgentCfg)
    suppressions: list = field(default_factory=list)


class ConfigError(Exception):
    """Human-readable config validation failure."""


def _as_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return default


def _merge_dataclass(dc_cls, data: dict):
    if not isinstance(data, dict):
        return dc_cls()
    kwargs = {}
    for f in dc_cls.__dataclass_fields__:
        if f not in data:
            continue
        val = data[f]
        field_type = dc_cls.__dataclass_fields__[f].type
        # nested dataclasses by name
        nested = {
            "WhatsAppCfg": WhatsAppCfg,
            "EmailCfg": EmailCfg,
            "WebhookCfg": WebhookCfg,
            "SyslogCfg": SyslogCfg,
            "QuietHoursCfg": QuietHoursCfg,
            "AlertingCfg": AlertingCfg,
            "ResponseCfg": ResponseCfg,
            "ThreatIntelCfg": ThreatIntelCfg,
            "DashboardCfg": DashboardCfg,
            "CentralCfg": CentralCfg,
            "LoggingCfg": LoggingCfg,
            "NetworkCfg": NetworkCfg,
            "AgentCfg": AgentCfg,
        }
        # resolve string annotations
        ft = field_type if isinstance(field_type, type) else None
        name = field_type if isinstance(field_type, str) else getattr(field_type, "__name__", "")
        if name in nested and isinstance(val, dict):
            kwargs[f] = _merge_dataclass(nested[name], val)
        else:
            kwargs[f] = val
    try:
        return dc_cls(**{k: v for k, v in kwargs.items() if k in dc_cls.__dataclass_fields__})
    except TypeError:
        return dc_cls()


def parse_config(raw: dict) -> SentinelConfig:
    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a JSON object")
    cfg = SentinelConfig()
    if "version" in raw:
        cfg.version = str(raw["version"])
    if "client_name" in raw:
        cfg.client_name = str(raw["client_name"])
    if "network" in raw:
        cfg.network = _merge_dataclass(NetworkCfg, raw["network"])
    if "alerting" in raw:
        a = raw["alerting"] if isinstance(raw["alerting"], dict) else {}
        cfg.alerting = AlertingCfg(
            whatsapp=_merge_dataclass(WhatsAppCfg, a.get("whatsapp") or {}),
            email=_merge_dataclass(EmailCfg, a.get("email") or {}),
            webhook=_merge_dataclass(WebhookCfg, a.get("webhook") or {}),
            syslog=_merge_dataclass(SyslogCfg, a.get("syslog") or {}),
            quiet_hours=_merge_dataclass(QuietHoursCfg, a.get("quiet_hours") or {}),
            dedup_minutes=int(a.get("dedup_minutes") or 15),
        )
    if "response" in raw:
        cfg.response = _merge_dataclass(ResponseCfg, raw["response"])
    if "threat_intel" in raw:
        cfg.threat_intel = _merge_dataclass(ThreatIntelCfg, raw["threat_intel"])
    if "dashboard" in raw:
        cfg.dashboard = _merge_dataclass(DashboardCfg, raw["dashboard"])
    if "central" in raw:
        cfg.central = _merge_dataclass(CentralCfg, raw["central"])
    if "logging" in raw:
        cfg.logging = _merge_dataclass(LoggingCfg, raw["logging"])
    if "agent" in raw:
        cfg.agent = _merge_dataclass(AgentCfg, raw["agent"])
    if "suppressions" in raw and isinstance(raw["suppressions"], list):
        cfg.suppressions = raw["suppressions"]
    validate(cfg)
    return cfg


def validate(cfg: SentinelConfig) -> None:
    errors = []
    if cfg.dashboard.port < 1 or cfg.dashboard.port > 65535:
        errors.append(f"dashboard.port out of range: {cfg.dashboard.port}")
    if cfg.alerting.dedup_minutes < 0:
        errors.append("alerting.dedup_minutes must be >= 0")
    if cfg.logging.level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        errors.append(f"logging.level invalid: {cfg.logging.level}")
    if cfg.alerting.email.enabled:
        if not cfg.alerting.email.smtp_server:
            errors.append("email enabled but smtp_server is empty")
        if not cfg.alerting.email.to_emails:
            errors.append("email enabled but to_emails is empty")
    if cfg.alerting.webhook.enabled and not cfg.alerting.webhook.url:
        errors.append("webhook enabled but url is empty")
    if cfg.central.enabled and not cfg.central.server_url:
        errors.append("central.enabled but server_url is empty")
    if cfg.threat_intel.enabled and not (cfg.threat_intel.abuseipdb_key or cfg.threat_intel.otx_key):
        errors.append("threat_intel.enabled but no API keys set")
    if errors:
        raise ConfigError("Invalid config:\n  - " + "\n  - ".join(errors))


def load_config(path: Optional[Path] = None) -> SentinelConfig:
    path = path or config_path()
    if not path.exists():
        cfg = SentinelConfig()
        save_config(cfg, path)
        return cfg
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ConfigError(f"Config JSON is corrupt ({path}): {e}") from e
    return parse_config(raw)


def save_config(cfg: SentinelConfig, path: Optional[Path] = None) -> None:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(cfg), indent=2))
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def config_wizard() -> SentinelConfig:
    """Interactive minimal wizard."""
    print("SENTINEL config wizard (blank = keep default)\n")
    cfg = SentinelConfig()
    name = input(f"Client name [{cfg.client_name}]: ").strip()
    if name:
        cfg.client_name = name
    sub = input("Primary subnet (e.g. 192.168.1.0/24, blank=auto): ").strip()
    if sub:
        cfg.network.subnets = [sub]
        cfg.network.auto_detect = False
    wa = input("Enable WhatsApp alerts? [y/N]: ").strip().lower()
    if wa == "y":
        cfg.alerting.whatsapp.enabled = True
        cfg.alerting.whatsapp.phone = input("  Phone (E.164): ").strip()
        cfg.alerting.whatsapp.apikey = input("  CallMeBot/API key: ").strip()
    print("\n[+] Config ready — write with save_config()")
    return cfg


def print_config(cfg: SentinelConfig) -> None:
    print(json.dumps(asdict(cfg), indent=2))
