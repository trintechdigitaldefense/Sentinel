# © 2026 TrinTech Digital Defense — installer safety tests
from __future__ import annotations

import json

import pytest


def test_init_config_preserves_malformed_existing_file(tmp_path, monkeypatch, capsys):
    import setup as setup_mod

    config = tmp_path / "config.json"
    original = b'{"alerting": {"email": "broken"'
    config.write_bytes(original)
    monkeypatch.setattr(setup_mod, "CONFIG", config)

    with pytest.raises(SystemExit) as exc:
        setup_mod.init_config()

    assert exc.value.code == 1
    assert config.read_bytes() == original
    assert "refusing to overwrite" in capsys.readouterr().out


def test_init_config_rejects_non_object_without_overwrite(tmp_path, monkeypatch):
    import setup as setup_mod

    config = tmp_path / "config.json"
    original = b'["not", "a", "config", "object"]'
    config.write_bytes(original)
    monkeypatch.setattr(setup_mod, "CONFIG", config)

    with pytest.raises(SystemExit):
        setup_mod.init_config()

    assert config.read_bytes() == original


def test_init_config_merges_defaults_without_losing_existing_secrets(tmp_path, monkeypatch):
    import setup as setup_mod

    config = tmp_path / "config.json"
    existing = {"alerting": {"email": {"password": "preserve-this"}}}
    config.write_text(json.dumps(existing), encoding="utf-8")
    monkeypatch.setattr(setup_mod, "CONFIG", config)

    setup_mod.init_config()

    updated = json.loads(config.read_text(encoding="utf-8"))
    assert updated["alerting"]["email"]["password"] == "preserve-this"
    assert "dashboard" in updated
    assert config.stat().st_mode & 0o777 == 0o600
