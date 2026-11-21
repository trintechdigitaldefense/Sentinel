# © 2026 TrinTech Digital Defense — authorized defensive use only
import json

import pytest


def test_key_issuance_refuses_to_overwrite_invalid_config(tmp_path, monkeypatch):
    home = tmp_path / "sentinel-home"
    central = tmp_path / "central"
    home.mkdir()
    config = home / "config.json"
    config.write_text("{corrupt")
    monkeypatch.setenv("SENTINEL_DIR", str(home))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(central))

    from modules.agent_enroll_ux import issue_local_agent_key

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        issue_local_agent_key("site-a")
    assert config.read_text() == "{corrupt"


def test_legacy_key_migration_is_reported_and_replacement_invalidates_old_key(tmp_path, monkeypatch):
    home = tmp_path / "sentinel-home"
    central = tmp_path / "central"
    home.mkdir()
    config = home / "config.json"
    config.write_text(json.dumps({
        "agent": {"master_key": "test-master", "shared_token": "legacy-local-token"}
    }))
    monkeypatch.setenv("SENTINEL_DIR", str(home))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(central))

    from modules.agent_keys import _hash, _keys_path, verify_key
    from modules.agent_enroll_ux import enroll_status, issue_local_agent_key

    _keys_path().parent.mkdir(parents=True, exist_ok=True)
    _keys_path().write_text(json.dumps({
        "agents": {
            "old-site": {
                "key_hash": _hash("old-site-key"),
                "created": "2025-01-01T00:00:00+00:00",
                "revoked": False,
            }
        }
    }))
    status = enroll_status()
    assert status["ok"] is True
    assert status["legacy_agents"] == ["old-site"]
    assert status["migration_required_agents"] == ["old-site"]
    assert status["migration_required_count"] == 1

    result = issue_local_agent_key("old-site")
    assert result["ok"] is True
    assert result["legacy_migration"] is True
    assert "invalidated immediately" in result["migration_note"]
    assert verify_key("old-site", "old-site-key") is False
    assert verify_key("old-site", result["api_key"]) is True
    assert "http://" not in result["hint"]
    assert (config.stat().st_mode & 0o777) == 0o600



def test_enroll_status_recognizes_installed_agent_https_configuration(tmp_path, monkeypatch):
    home = tmp_path / "sentinel-home"
    central = tmp_path / "central"
    home.mkdir()
    (home / "config.json").write_text(json.dumps({
        "agent": {
            "central_url": "https://central.example.test:8743",
            "shared_token": "agent-api-key",
        }
    }))
    monkeypatch.setenv("SENTINEL_DIR", str(home))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(central))

    from modules.agent_enroll_ux import enroll_status

    status = enroll_status()
    assert status["ok"] is True
    assert status["enrolled"] is True
    assert status["server_url"] == "https://central.example.test:8743"
