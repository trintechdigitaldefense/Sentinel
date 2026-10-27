
from __future__ import annotations

def test_merge_discovery_and_status():
    from modules.network_fleet import merge_discovery, fleet_status, set_supervised, supervised_enabled
    set_supervised(True)
    assert supervised_enabled() is True
    db = merge_discovery()
    assert "devices" in db and "count" in db
    st = fleet_status()
    assert st.get("ok") is True
    assert isinstance(st.get("devices"), dict)

def test_queue_review():
    from modules.network_fleet import queue_for_review, list_pending_review, resolve_review
    r = queue_for_review("TEST_EVENT", {"x": 1}, severity="HIGH")
    assert r.get("ok") and r.get("id")
    pending = list_pending_review()
    assert any(p.get("id") == r["id"] for p in pending)
    done = resolve_review(r["id"], "approve")
    assert done.get("ok")
