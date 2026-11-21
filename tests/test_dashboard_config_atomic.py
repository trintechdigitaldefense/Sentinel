# © 2026 TrinTech Digital Defense — atomic dashboard config tests
from __future__ import annotations

import json
import os

import pytest


def test_save_cfg_atomically_writes_private_json(tmp_path, monkeypatch):
    import modules.dashboard_impl as dashboard

    monkeypatch.setattr(dashboard, "_home", lambda: tmp_path)
    dashboard._save_cfg({"dashboard": {"role": "viewer"}})

    config = tmp_path / "config.json"
    assert json.loads(config.read_text(encoding="utf-8")) == {"dashboard": {"role": "viewer"}}
    assert config.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.glob(".config.json.*.tmp")) == []


def test_save_cfg_replace_failure_preserves_original_and_cleans_temp(tmp_path, monkeypatch):
    import modules.dashboard_impl as dashboard

    config = tmp_path / "config.json"
    original = b'{"customer":"preserve"}\n'
    config.write_bytes(original)
    monkeypatch.setattr(dashboard, "_home", lambda: tmp_path)

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(dashboard.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        dashboard._save_cfg({"customer": "new"})

    assert config.read_bytes() == original
    assert list(tmp_path.glob(".config.json.*.tmp")) == []


@pytest.mark.parametrize("kind", ["symlink", "dangling", "fifo"])
def test_save_cfg_refuses_symlink_and_special_files(tmp_path, monkeypatch, kind):
    import modules.dashboard_impl as dashboard

    config = tmp_path / "config.json"
    if kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text('{"customer":"keep"}', encoding="utf-8")
        config.symlink_to(target)
    elif kind == "dangling":
        config.symlink_to(tmp_path / "missing.json")
    else:
        os.mkfifo(config)
    monkeypatch.setattr(dashboard, "_home", lambda: tmp_path)

    with pytest.raises((ValueError, OSError)):
        dashboard._save_cfg({"customer": "replace"})

    assert config.is_symlink() if kind != "fifo" else config.is_fifo()


def test_save_cfg_refuses_malformed_existing_config_without_overwrite(tmp_path, monkeypatch):
    import modules.dashboard_impl as dashboard

    config = tmp_path / "config.json"
    original = b'{"broken":'
    config.write_bytes(original)
    monkeypatch.setattr(dashboard, "_home", lambda: tmp_path)

    with pytest.raises(json.JSONDecodeError):
        dashboard._save_cfg({"customer": "replace"})

    assert config.read_bytes() == original
    assert list(tmp_path.glob(".config.json.*.tmp")) == []


def test_save_cfg_file_fsync_failure_preserves_original_and_cleans_temp(
    tmp_path, monkeypatch
):
    """A durability failure must not replace the last valid configuration."""
    import modules.dashboard_impl as dashboard

    config = tmp_path / "config.json"
    original = b'{"customer":"preserve-on-fsync-error"}\\n'
    config.write_bytes(original)
    monkeypatch.setattr(dashboard, "_home", lambda: tmp_path)

    def fail_fsync(_fd):
        raise OSError("simulated file fsync failure")

    monkeypatch.setattr(dashboard.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="simulated file fsync failure"):
        dashboard._save_cfg({"customer": "new"})

    assert config.read_bytes() == original
    assert list(tmp_path.glob(".config.json.*.tmp")) == []
