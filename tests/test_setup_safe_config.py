# © 2026 TrinTech Digital Defense — authorized defensive use only
import importlib.util
import json
from pathlib import Path

import pytest


def _load_setup_module():
    path = Path(__file__).resolve().parents[1] / "setup.py"
    spec = importlib.util.spec_from_file_location("sentinel_setup_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_invalid_existing_config_is_preserved_and_setup_stops(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "sentinel-home"))
    setup = _load_setup_module()
    setup.HOME.mkdir(parents=True, exist_ok=True)
    original = "{invalid json"
    setup.CONFIG.write_text(original)

    with pytest.raises(SystemExit) as exc:
        setup.init_config()

    assert exc.value.code == 2
    assert setup.CONFIG.read_text() == original
    assert setup.CONFIG.with_name("config.json.corrupt").read_text() == original


def test_valid_existing_config_is_merged_without_losing_client_values(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "sentinel-home"))
    setup = _load_setup_module()
    setup.HOME.mkdir(parents=True, exist_ok=True)
    setup.CONFIG.write_text(json.dumps({"client_name": "Existing Client", "custom": {"keep": True}}))

    setup.init_config()

    updated = json.loads(setup.CONFIG.read_text())
    assert updated["client_name"] == "Existing Client"
    assert updated["custom"] == {"keep": True}
    assert "network" in updated
    assert (setup.CONFIG.stat().st_mode & 0o777) == 0o600
