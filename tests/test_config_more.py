# © 2026 TrinTech Digital Defense — authorized defensive use only
import pytest
from modules.config_schema import parse_config, ConfigError


def test_bad_log_level():
    with pytest.raises(ConfigError):
        parse_config({"logging": {"level": "VERBOSE"}})


def test_webhook_needs_url():
    with pytest.raises(ConfigError):
        parse_config({"alerting": {"webhook": {"enabled": True, "url": ""}}})


def test_central_needs_url():
    with pytest.raises(ConfigError):
        parse_config({"central": {"enabled": True, "server_url": ""}})


def test_threat_intel_needs_keys():
    with pytest.raises(ConfigError):
        parse_config({"threat_intel": {"enabled": True}})


def test_dedup_negative():
    with pytest.raises(ConfigError):
        parse_config({"alerting": {"dedup_minutes": -1}})


def test_valid_full():
    cfg = parse_config({
        "client_name": "Lab",
        "dashboard": {"port": 8792},
        "alerting": {"dedup_minutes": 10},
    })
    assert cfg.client_name == "Lab"
