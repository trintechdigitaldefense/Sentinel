# © 2026 TrinTech Digital Defense — authorized defensive use only
from pathlib import Path
from modules.self_defense import create_baseline, verify, hash_file


def test_baseline_and_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    root = Path(__file__).resolve().parents[1]
    r = create_baseline(root)
    assert r["ok"] and r["count"] > 0
    v = verify(root)
    assert v["ok"] is True


def test_hash_file():
    p = Path(__file__)
    h = hash_file(p)
    assert len(h) == 64
