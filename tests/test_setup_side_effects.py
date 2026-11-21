from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_setup_import_has_no_config_side_effect(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    monkeypatch.delenv("SENTINEL_SIEM", raising=False)
    import runpy

    runpy.run_path(str(ROOT / "setup.py"), run_name="sentinel_setup_import_test")
    assert not (tmp_path / "config.json").exists()


def test_setup_check_does_not_create_config_or_run_source_wiring(tmp_path):
    env = os.environ.copy()
    env["SENTINEL_DIR"] = str(tmp_path / "sentinel-home")
    env.pop("SENTINEL_SIEM", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(ROOT / "setup.py"), "--check"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "sentinel-home" / "config.json").exists()
    assert "Check-only mode — no writes" in result.stdout


def test_check_engine_compiles_without_creating_bytecode(tmp_path, monkeypatch):
    import runpy

    namespace = runpy.run_path(str(ROOT / "setup.py"), run_name="sentinel_setup_test")
    engine = tmp_path / "sentinel.py"
    engine.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setitem(namespace, "ENGINE", engine)
    assert namespace["check_engine"]() is True
    assert not (tmp_path / "__pycache__").exists()


def test_enable_defaults_false_is_safe_and_preserves_explicit_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules.siem import enable_defaults

    config = {
        "dashboard": {"allow_control": False},
        "alerting": {"siem": {"enabled": True, "ship_file": {"enabled": False}}},
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    result = enable_defaults(False)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert result["siem_enabled"] is True
    assert result["ship_file_enabled"] is False
    assert saved["dashboard"]["allow_control"] is False
    assert saved["alerting"]["siem"]["ship_file"]["enabled"] is False
    assert path.stat().st_mode & 0o777 == 0o600


def test_enable_defaults_false_does_not_enable_ship_file_or_dashboard_control(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules.siem import enable_defaults

    result = enable_defaults(False)
    saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert result["siem_enabled"] is False
    assert result["ship_file_enabled"] is False
    assert saved["alerting"]["siem"]["ship_file"]["enabled"] is False
    assert "dashboard" not in saved


def test_enable_defaults_refuses_malformed_config_without_overwrite(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules.siem import enable_defaults

    path = tmp_path / "config.json"
    original = b'{"broken":'
    path.write_bytes(original)
    with pytest.raises(RuntimeError, match="refusing to replace"):
        enable_defaults(False)
    assert path.read_bytes() == original


def test_enable_defaults_refuses_symlink(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules.siem import enable_defaults

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    (tmp_path / "config.json").symlink_to(target)
    with pytest.raises(RuntimeError, match="symbolic link"):
        enable_defaults(False)
    assert target.read_text(encoding="utf-8") == "{}"


def test_enable_defaults_replace_failure_preserves_original(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    import modules.siem as siem

    path = tmp_path / "config.json"
    original = b'{"keep":"me"}'
    path.write_bytes(original)

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(siem.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        siem.enable_defaults(False)
    assert path.read_bytes() == original
    assert list(tmp_path.glob(".config.json.*.tmp")) == []


def test_setup_contains_no_runtime_source_wiring():
    source = (ROOT / "setup.py").read_text(encoding="utf-8")
    assert "apply_cases_wire" not in source
    assert "apply_dashboard_cases" not in source
    assert "scripts/apply_cases_wire.py" not in source
    assert "scripts/apply_dashboard_cases.py" not in source
