# © 2026 TrinTech Digital Defense — authorized defensive use only
from modules.severity import score, list_model, ORDER, BASE


def test_all_base_types_have_severity():
    for t, sev in BASE.items():
        assert sev in ORDER
        assert score(t) == sev


def test_reverse_shell_critical():
    assert score("REVERSE_SHELL") == "CRITICAL"


def test_canary_high():
    assert score("CANARY_TRIGGERED") == "HIGH"
    assert score("DECOY_MODIFIED") == "HIGH"


def test_intel_escalation():
    assert score("NEW_DEVICE", context={"intel_malicious": True}) in ("HIGH", "CRITICAL")


def test_repeated_escalation():
    assert score("USB_INSERT", context={"repeated": 5}) in ("HIGH", "MEDIUM", "LOW")


def test_fim_etc_escalation():
    assert score("FIM_MODIFIED", context={"path": "/etc/passwd"}) == "HIGH"


def test_unknown_type_low():
    assert score("SOMETHING_NEW") == "LOW"


def test_list_model():
    m = list_model()
    assert "base" in m and "order" in m
