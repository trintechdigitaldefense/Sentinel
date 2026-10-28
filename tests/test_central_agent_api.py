from __future__ import annotations

def test_agent_handler_exists():
    import sentinel
    assert hasattr(sentinel, "AgentHandler")
    assert hasattr(sentinel, "start_central_listener")
    # token method present
    assert hasattr(sentinel.AgentHandler, "_token_ok")
    assert hasattr(sentinel.AgentHandler, "do_POST")
    assert hasattr(sentinel.AgentHandler, "do_GET")
