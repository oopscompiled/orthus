from __future__ import annotations

from examples.support_copilot import demo as support_demo


def test_demo_module_loads() -> None:
    assert hasattr(support_demo, "run_demo")
    assert hasattr(support_demo, "build_scenarios")


def test_scenarios_non_empty() -> None:
    scenarios = support_demo.build_scenarios()
    assert scenarios


def test_support_copilot_demo_has_safe_and_blocked_paths() -> None:
    results = support_demo.run_demo(debug=False, as_json=False, print_output=False)
    decisions = {r.decision for r in results}
    assert ("block" in decisions) or ("require_approval" in decisions)
    assert ("allow" in decisions) or ("log_only" in decisions)
