# © 2026 TrinTech Digital Defense — authorized defensive use only
import importlib


def test_firewall_event_is_written_to_case_record(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "sentinel-home"))

    import modules.cases as cases
    import modules.firewall as firewall

    importlib.reload(cases)
    importlib.reload(firewall)

    detail = {"action": "block", "ip": "192.0.2.25", "reason": "test event"}
    firewall._case_event("Firewall block test", detail)

    rows = cases.list_cases(limit=10)
    matching = [row for row in rows if row["title"] == "Firewall block test"]
    assert len(matching) == 1
    assert matching[0]["source"] == "firewall"

    case = cases.get_case(matching[0]["id"])
    assert case["summary"]
    assert '"ip": "192.0.2.25"' in case["summary"]
    assert any(note["author"] == "sentinel_firewall" for note in case["notes"])
