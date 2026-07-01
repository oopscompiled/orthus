from __future__ import annotations

from examples.mcp_gateway_proxy import proxy as mcp_proxy


def test_mcp_gateway_proxy_module_loads() -> None:
    assert hasattr(mcp_proxy, "run_demo")
    assert hasattr(mcp_proxy, "guard_mcp_event")


def test_mcp_gateway_proxy_fixtures_non_empty() -> None:
    events = mcp_proxy.build_demo_events()
    assert len(events) >= 4


def test_mcp_gateway_proxy_has_safe_and_guarded_paths() -> None:
    rows = mcp_proxy.run_demo(as_json=False, print_output=False)
    decisions = {row["decision"] for row in rows}
    assert ("allow" in decisions) or ("log_only" in decisions)
    assert ("block" in decisions) or ("require_approval" in decisions)


def test_mcp_gateway_proxy_metadata_reason_present() -> None:
    rows = mcp_proxy.run_demo(as_json=False, print_output=False)
    all_reasons = {reason for row in rows for reason in row["reason_codes"]}
    assert "mcp_tool_descriptor_tampering" in all_reasons or "schema_coercion_argument_risk" in all_reasons
