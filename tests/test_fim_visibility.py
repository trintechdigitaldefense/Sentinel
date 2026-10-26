# © 2026 TrinTech Digital Defense
from __future__ import annotations

from modules.fim_realtime import visibility_status, has_inotifywait


def test_visibility_status_shape():
    st = visibility_status()
    assert st.get("ok") is True
    assert "inotifywait" in st
    assert "incomplete" in st
    assert st["inotifywait"] is has_inotifywait()
    if not st["inotifywait"]:
        assert st["incomplete"] is True
