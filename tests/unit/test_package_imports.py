from __future__ import annotations


def test_public_imports_and_engine_init() -> None:
    from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, ToolCall
    from api.integrations.anthropic import guard_tool, guard_tool_call
    from api.server.app import app

    assert app is not None
    assert Actor is not None
    assert ToolCall is not None
    assert FirewallRequest is not None
    assert guard_tool is not None
    assert guard_tool_call is not None

    engine = FirewallEngine()
    assert engine is not None
    assert len(engine.rules_engine.rules) > 0
    # Default bundled policy should load for package/runtime usage.
    assert engine.policy_engine is not None
