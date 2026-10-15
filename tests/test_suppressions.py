# © 2026 TrinTech Digital Defense — authorized defensive use only
from modules.alerts_cli import add_suppression, is_suppressed, ack_alert, list_alerts, _load_state


def test_add_and_match(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = add_suppression("USB_INSERT", "Kingston", note="lab")
    assert r["ok"]
    assert is_suppressed("USB_INSERT", "USB Kingston device added")
    assert not is_suppressed("REVERSE_SHELL", "bash -i")


def test_ack(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = ack_alert("fp-abc")
    assert r["ok"]
    st = _load_state()
    assert "fp-abc" in st["acked"]


def test_list_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    assert list_alerts() == []
