# © 2026 TrinTech Digital Defense — authorized defensive use only
from modules.config_schema import parse_config, ConfigError, SentinelConfig, validate


def test_default_parses():
    cfg = parse_config({})
    assert cfg.client_name == "Client"
    assert cfg.dashboard.port == 8792


def test_bad_port():
    try:
        parse_config({"dashboard": {"port": 99999}})
        assert False, "should raise"
    except ConfigError as e:
        assert "port" in str(e).lower()


def test_email_requires_server():
    try:
        parse_config({"alerting": {"email": {"enabled": True, "smtp_server": "", "to_emails": ["a@b.c"]}}})
        assert False
    except ConfigError:
        pass
