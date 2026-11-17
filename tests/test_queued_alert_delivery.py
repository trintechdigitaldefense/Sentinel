from modules import alerting, phase4


def test_queued_delivery_bypasses_dedup_and_does_not_requeue(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    deliveries = []

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def starttls(self):
            pass

        def sendmail(self, sender, recipients, message):
            deliveries.append((sender, recipients, message))

        def quit(self):
            pass

    monkeypatch.setattr(alerting.smtplib, "SMTP", FakeSMTP)

    engine = alerting.AlertEngine({
        "email": {
            "enabled": True,
            "smtp_server": "smtp.test.invalid",
            "smtp_port": 587,
            "to_emails": ["test@example.invalid"],
            "use_tls": True,
        }
    })

    # Establish a dedup record for this fingerprint.
    first = engine.send("HIGH", "queued-alert", "detail")
    assert first["sent"] is True

    # A queued retry must still deliver despite that record.
    phase4.offline_enqueue(
        "queued-alert",
        {"severity": "HIGH", "detail": "detail", "meta": {"type": "test"}},
    )

    result = phase4.offline_flush(engine.send_queued)

    assert result["flushed"] == 1
    assert result["errors"] == 0
    assert result["retained"] == 0
    assert len(deliveries) == 2
    assert phase4.offline_status()["count"] == 0


def test_failed_queued_delivery_does_not_reenqueue(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    engine = alerting.AlertEngine({})
    result = engine.send_queued(
        "queued-alert",
        {"severity": "HIGH", "detail": "offline"},
    )

    assert result["sent"] is False
    assert result.get("queued_offline") is None
    assert phase4.offline_status()["count"] == 0


def test_failed_initial_delivery_is_queued_and_retried(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    deliveries = []

    class FakeSMTP:
        fail = True

        def __init__(self, *args, **kwargs):
            pass

        def starttls(self):
            pass

        def sendmail(self, sender, recipients, message):
            if type(self).fail:
                raise OSError("temporary SMTP failure")
            deliveries.append((sender, recipients, message))

        def quit(self):
            pass

    monkeypatch.setattr(alerting.smtplib, "SMTP", FakeSMTP)

    engine = alerting.AlertEngine({
        "email": {
            "enabled": True,
            "smtp_server": "smtp.test.invalid",
            "smtp_port": 587,
            "to_emails": ["test@example.invalid"],
            "use_tls": True,
        }
    })

    first = engine.send("HIGH", "recoverable-alert", "detail")

    assert first["sent"] is False
    assert first["queued_offline"] is True
    assert phase4.offline_status()["count"] == 1

    FakeSMTP.fail = False

    result = phase4.offline_flush(engine.send_queued)

    assert result["flushed"] == 1
    assert result["errors"] == 0
    assert result["retained"] == 0
    assert len(deliveries) == 1
    assert phase4.offline_status()["count"] == 0
