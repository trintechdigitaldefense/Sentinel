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
    cfg = parse_config({"dashboard": {"remote_access": True, "cookie_secure": True, "trusted_hosts": ["sentinel.customer.com"]}})
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

def test_dashboard_secure_cookie_requires_remote_access_mode():
    try:
        parse_config({"dashboard": {"remote_access": False, "cookie_secure": True}})
        assert False, "secure cookies require remote TLS proxy mode"
    except ConfigError as e:
        assert "remote_access=true" in str(e)


def test_dashboard_local_mode_defaults_to_loopback_hosts():
    cfg = parse_config({})
    assert cfg.dashboard.remote_access is False
    assert cfg.dashboard.trusted_hosts == []


def test_dashboard_remote_mode_requires_trusted_hosts():
    try:
        parse_config({
            "dashboard": {
                "remote_access": True,
                "cookie_secure": True,
            }
        })
        assert False, "remote dashboard must require explicit trusted hosts"
    except ConfigError as e:
        assert "trusted_hosts" in str(e)


def test_dashboard_remote_mode_accepts_explicit_customer_hostname():
    cfg = parse_config({
        "dashboard": {
            "remote_access": True,
            "cookie_secure": True,
            "trusted_hosts": ["sentinel.customer.com"],
        }
    })
    assert cfg.dashboard.trusted_hosts == ["sentinel.customer.com"]





def test_dashboard_remote_mode_accepts_ipv4_trusted_host():
    cfg = parse_config({"dashboard": {"remote_access": True, "cookie_secure": True, "trusted_hosts": ["192.0.2.10"]}})
    assert cfg.dashboard.trusted_hosts == ["192.0.2.10"]


def test_dashboard_remote_mode_accepts_ipv6_trusted_host():
    cfg = parse_config({"dashboard": {"remote_access": True, "cookie_secure": True, "trusted_hosts": ["2001:db8::10"]}})
    assert cfg.dashboard.trusted_hosts == ["2001:db8::10"]

def test_dashboard_trusted_hosts_must_be_a_list_of_strings():
    for value in ("sentinel.customer.com", None, 123):
        try:
            parse_config({
                "dashboard": {
                    "remote_access": True,
                    "cookie_secure": True,
                    "trusted_hosts": value,
                }
            })
            assert False, f"invalid trusted_hosts accepted: {value!r}"
        except ConfigError as e:
            assert "trusted_hosts" in str(e)


def test_dashboard_trusted_hosts_reject_malformed_entries():
    for host in ("", "https://sentinel.customer.com", "bad host", "*.customer.com", "user@host"):
        try:
            parse_config({
                "dashboard": {
                    "remote_access": True,
                    "cookie_secure": True,
                    "trusted_hosts": [host],
                }
            })
            assert False, f"malformed trusted host accepted: {host!r}"
        except ConfigError as e:
            assert "trusted_hosts" in str(e)
