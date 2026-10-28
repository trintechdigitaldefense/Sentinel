from __future__ import annotations

def test_agent_handler_exists():
    import sentinel
    assert hasattr(sentinel, "AgentHandler")
    assert hasattr(sentinel, "start_central_listener")
    from modules.central_agent import CentralAgentHandler, start_central
    assert hasattr(CentralAgentHandler, "_token_ok")
    assert hasattr(CentralAgentHandler, "do_POST")
    assert hasattr(CentralAgentHandler, "do_GET")
    assert callable(start_central)
