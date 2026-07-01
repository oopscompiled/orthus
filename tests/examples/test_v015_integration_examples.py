from __future__ import annotations

from pathlib import Path

from examples.demos._runner import run_demo
from examples.langchain_style_tool_guard import demo as langchain_demo


DEMOS_DIR = Path(__file__).resolve().parents[2] / "examples" / "demos"


def test_langchain_style_demo_has_allowed_and_guarded_paths() -> None:
    rows = langchain_demo.run_demo(as_json=False, print_output=False)
    statuses = {row["outcome"]["status"] for row in rows}
    assert "executed" in statuses
    assert "blocked" in statuses or "approval_required" in statuses


def test_demo_package_scenarios_match_expected_decisions() -> None:
    demo_dirs = sorted(path for path in DEMOS_DIR.iterdir() if (path / "event.json").exists())
    assert len(demo_dirs) == 4

    rows = [run_demo(path, print_output=False) for path in demo_dirs]
    assert all(row["passed"] for row in rows)


def test_demo_package_includes_market_messages() -> None:
    expected_messages = {
        "The model got confused. The action boundary did not.",
        "Tool metadata is not authority.",
        "Text cannot manufacture approval.",
        "Orthus is not a keyword blocker.",
    }
    messages = set()
    for path in DEMOS_DIR.iterdir():
        expected_path = path / "expected_decision.json"
        if not expected_path.exists():
            continue
        row = run_demo(path, print_output=False)
        messages.add(row["expected"].get("message"))

    assert messages == expected_messages
