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


def test_dashboard_remote_tls_settings_are_explicit_and_round_trip():
    cfg = parse_config({"dashboard": {"remote_access": True, "cookie_secure": True}})
    assert cfg.dashboard.remote_access is True
    assert cfg.dashboard.cookie_secure is True


def test_dashboard_remote_access_requires_secure_cookie():
    try:
        parse_config({"dashboard": {"remote_access": True, "cookie_secure": False}})
        assert False, "remote dashboard must require secure cookies"
    except ConfigError as e:
        assert "cookie_secure" in str(e)


def test_dashboard_tls_settings_must_be_booleans():
    try:
        parse_config({"dashboard": {"remote_access": "true", "cookie_secure": "true"}})
        assert False, "string booleans must be rejected"
    except ConfigError as e:
        assert "must be a boolean" in str(e)
