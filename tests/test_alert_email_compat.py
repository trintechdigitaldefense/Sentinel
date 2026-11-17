import os
from unittest.mock import patch

from modules.alerting import AlertEngine, normalize_alerting_config


def test_legacy_email_configuration_is_normalized():
    original = {
        "email": {
            "enabled": True,
            "smtp_server": "smtp.example.test",
            "smtp_port": 587,
            "from_email": "sender@example.test",
            "app_password": "test-secret",
            "to_email": "one@example.test; two@example.test",
        }
    }

    normalized = normalize_alerting_config(original)

    assert normalized["email"]["to_emails"] == [
        "one@example.test",
        "two@example.test",
    ]
    assert normalized["email"]["username"] == "sender@example.test"
    assert normalized["email"]["password"] == "test-secret"
    assert "to_emails" not in original["email"]


def test_existing_router_email_settings_are_preserved():
    normalized = normalize_alerting_config({
        "email": {
            "enabled": True,
            "to_emails": ["first@example.test", "second@example.test"],
            "to_email": "legacy@example.test",
            "username": "router-user",
            "password": "router-password",
            "from_email": "sender@example.test",
        }
    })

    assert normalized["email"]["to_emails"] == [
        "first@example.test",
        "second@example.test",
    ]
    assert normalized["email"]["username"] == "router-user"
    assert normalized["email"]["password"] == "router-password"


def test_legacy_email_is_sent_through_router_with_mocked_smtp(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    config = normalize_alerting_config({
        "email": {
            "enabled": True,
            "smtp_server": "smtp.example.test",
            "smtp_port": 587,
            "from_email": "sender@example.test",
            "app_password": "test-secret",
            "to_email": "one@example.test; two@example.test",
        }
    })

    with patch("modules.alerting.smtplib.SMTP") as smtp_factory:
        smtp = smtp_factory.return_value

        result = AlertEngine(config).send(
            "HIGH",
            "Mocked SMTP test",
            detail="This test must never send a real email.",
        )

    assert result["ok"] is True
    assert result["sent"] is True
    assert not result.get("queued_offline", False)

    smtp_factory.assert_called_once_with(
        "smtp.example.test", 587, timeout=20
    )
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with(
        "sender@example.test", "test-secret"
    )
    smtp.sendmail.assert_called_once()

    recipients = smtp.sendmail.call_args.args[1]
    assert recipients == ["one@example.test", "two@example.test"]
