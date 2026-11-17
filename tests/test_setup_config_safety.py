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


def test_init_config_refuses_symlink_without_touching_target(tmp_path, monkeypatch):
    import setup as setup_mod

    target = tmp_path / "customer-config.json"
    original = b'{"customer": "keep"}'
    target.write_bytes(original)
    config = tmp_path / "config.json"
    config.symlink_to(target)
    monkeypatch.setattr(setup_mod, "CONFIG", config)

    with pytest.raises(SystemExit):
        setup_mod.init_config()

    assert config.is_symlink()
    assert target.read_bytes() == original


def test_init_config_refuses_dangling_symlink(tmp_path, monkeypatch):
    import setup as setup_mod

    config = tmp_path / "config.json"
    config.symlink_to(tmp_path / "missing-target.json")
    monkeypatch.setattr(setup_mod, "CONFIG", config)

    with pytest.raises(SystemExit):
        setup_mod.init_config()

    assert config.is_symlink()
    assert not (tmp_path / "missing-target.json").exists()



def test_init_config_rejects_fifo_without_blocking(tmp_path, monkeypatch):
    import os
    import setup as setup_mod

    config = tmp_path / "config.json"
    os.mkfifo(config)
    monkeypatch.setattr(setup_mod, "CONFIG", config)

    with pytest.raises(SystemExit) as exc:
        setup_mod.init_config()

    assert exc.value.code == 1
    assert config.exists()
    assert config.is_fifo()


def test_atomic_replace_failure_preserves_original_and_cleans_temp(tmp_path, monkeypatch):
    import setup as setup_mod

    config = tmp_path / "config.json"
    original = {"customer": "keep"}
    config.write_text(json.dumps(original), encoding="utf-8")
    before = config.read_bytes()
    monkeypatch.setattr(setup_mod, "CONFIG", config)

    def fail_replace(source, destination):
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(setup_mod.os, "replace", fail_replace)

    with pytest.raises(SystemExit):
        setup_mod.init_config()

    assert config.read_bytes() == before
    assert list(tmp_path.glob(".config.json.*.tmp")) == []
