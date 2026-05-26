from __future__ import annotations

from examples.mcp_server_guard import demo as mcp_demo


def test_demo_module_loads() -> None:
    assert hasattr(mcp_demo, "run_demo")
    assert hasattr(mcp_demo, "build_scenarios")


def test_scenarios_non_empty() -> None:
    scenarios = mcp_demo.build_scenarios()
    assert scenarios


def test_mcp_demo_has_safe_and_guarded_paths() -> None:
    results = mcp_demo.run_demo(debug=False, as_json=False, print_output=False)
    decisions = {r.decision for r in results}
    assert ("require_approval" in decisions) or ("block" in decisions)
    assert ("allow" in decisions) or ("log_only" in decisions)


def test_mcp_demo_stateful_signals_present() -> None:
    results = mcp_demo.run_demo(debug=False, as_json=False, print_output=False)
    reason_codes = {code for result in results for code in result.reason_codes}
    assert (
        "partial_subscription_flood" in reason_codes
        or "notify_after_unsubscribe" in reason_codes
    )
