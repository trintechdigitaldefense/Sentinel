# © 2026 TrinTech Digital Defense
from __future__ import annotations

import json
import os
import stat
from pathlib import Path


def test_create_baseline_mode_0600(tmp_path, monkeypatch):
    from modules import self_defense as sd

    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    # minimal repo tree
    (tmp_path / "repo").mkdir()
    eng = tmp_path / "repo" / "sentinel.py"
    eng.write_text("# test engine\n")
    (tmp_path / "repo" / "setup.py").write_text("# setup\n")
    mod = tmp_path / "repo" / "modules"
    mod.mkdir()
    (mod / "x.py").write_text("x = 1\n")

    out = sd.create_baseline(tmp_path / "repo")
    assert out.get("ok") is True
    path = Path(out["path"])
    assert path.exists()
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600 or mode == 0o600
    data = json.loads(path.read_text())
    assert "files" in data


def test_verify_detects_change(tmp_path, monkeypatch):
    from modules import self_defense as sd

    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir()
    f = repo / "sentinel.py"
    f.write_text("v1\n")
    (repo / "setup.py").write_text("s\n")
    (repo / "modules").mkdir()
    sd.create_baseline(repo)
    f.write_text("v2 tampered\n")
    result = sd.verify(repo)
    assert result.get("ok") is False
    assert result.get("changed")
