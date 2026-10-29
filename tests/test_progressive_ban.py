
from modules.brute_force import progressive_duration

def test_progressive_scales(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    ssh = {"max_block_duration": 86400, "repeat_multiplier": 2.0}
    d1 = progressive_duration("1.2.3.4", 1800, ssh)
    d2 = progressive_duration("1.2.3.4", 1800, ssh)
    d3 = progressive_duration("1.2.3.4", 1800, ssh)
    assert d1 == 1800
    assert d2 == 3600
    assert d3 == 7200
