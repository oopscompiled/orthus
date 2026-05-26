from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, FirewallResult, ToolCall


@dataclass(slots=True)
class DemoStep:
    title: str
    text: str
    tool_name: str
    tool_args: dict[str, object]
    actor_user_id: str = "mcp_user_1"
    actor_role: str = "user"


@dataclass(slots=True)
class DemoScenario:
    id: str
    title: str
    steps: list[DemoStep]


def build_scenarios() -> list[DemoScenario]:
    return [
        DemoScenario(
            id="normal_resource_read",
            title="Normal resource read",
            steps=[
                DemoStep(
                    title="normal read",
                    text="Read a workspace file.",
                    tool_name="resources/read",
                    tool_args={"uri": "file:///workspace/README.md"},
                )
            ],
        ),
        DemoScenario(
            id="sensitive_resource_read",
            title="Sensitive resource read",
            steps=[
                DemoStep(
                    title="sensitive read",
                    text="Read a sensitive resource.",
                    tool_name="resources/read",
                    tool_args={"uri": "file:///etc/shadow"},
                )
            ],
        ),
        DemoScenario(
            id="subscription_fanout_race",
            title="Subscription fanout/race",
            steps=[
                DemoStep(
                    title="fanout",
                    text="Subscribe race with high parallel ops.",
                    tool_name="subscribe_race",
                    tool_args={"uri": "file:///shared/", "parallel_ops": 100},
                )
            ],
        ),
        DemoScenario(
            id="partial_subscription_flood",
            title="Partial subscription flood",
            steps=[
                DemoStep(
                    title="partial #1",
                    text="Partial subscribe #1",
                    tool_name="resources/subscribe",
                    tool_args={"uri": "file:///shared/1.log", "complete_handshake": False},
                ),
                DemoStep(
                    title="partial #2",
                    text="Partial subscribe #2",
                    tool_name="resources/subscribe",
                    tool_args={"uri": "file:///shared/2.log", "complete_handshake": False},
                ),
                DemoStep(
                    title="partial #3",
                    text="Partial subscribe #3",
                    tool_name="resources/subscribe",
                    tool_args={"uri": "file:///shared/3.log", "complete_handshake": False},
                ),
            ],
        ),
        DemoScenario(
            id="unsubscribe_notify_after_free",
            title="Unsubscribe then notify after free",
            steps=[
                DemoStep(
                    title="unsubscribe",
                    text="Unsubscribe replay-like token.",
                    tool_name="resources/unsubscribe",
                    tool_args={"subscription_id": "sub_123_stolen"},
                ),
                DemoStep(
                    title="notify",
                    text="Notify same subscription with use-after-free marker.",
                    tool_name="resources/notify",
                    tool_args={"subscription_id": "sub_123_stolen", "data": "after_free"},
                ),
            ],
        ),
    ]


def _row_dict(
    scenario: DemoScenario,
    step_idx: int,
    step: DemoStep,
    result: FirewallResult,
) -> dict[str, Any]:
    return {
        "scenario_id": scenario.id,
        "scenario_title": scenario.title,
        "step": step_idx,
        "step_title": step.title,
        "tool": step.tool_name,
        "decision": result.decision,
        "risk": result.risk,
        "reason_codes": result.reason_codes,
        "matched_rules": result.matched_rules,
        "session": result.updated_session_context,
        "normalized": result.normalized,
    }


def _print_table(rows: list[dict[str, Any]], *, debug: bool) -> None:
    print("ORTHUS MCP SERVER GUARD DEMO")
    print("Untrusted context can request actions, but it cannot grant authority.")
    print()
    print(f"{'Scenario':<36} | {'Tool':<24} | {'Decision':<16} | {'Risk':<5} | Reason codes")
    print("-" * 140)
    for row in rows:
        reasons = ", ".join(row["reason_codes"]) if row["reason_codes"] else "-"
        scenario_label = row["scenario_title"]
        if row["step"] > 1:
            scenario_label = f"{scenario_label} (step {row['step']})"
        print(
            f"{scenario_label[:36]:<36} | "
            f"{row['tool'][:24]:<24} | "
            f"{row['decision']:<16} | "
            f"{row['risk']:<5.2f} | "
            f"{reasons}"
        )
        if debug:
            print(f"  matched_rules: {', '.join(row['matched_rules']) if row['matched_rules'] else '-'}")
            print(f"  session: {json.dumps(row['session'], ensure_ascii=False)}")
            print(f"  normalized: {row['normalized']}")


def run_demo(*, debug: bool = False, as_json: bool = False, print_output: bool = True) -> list[FirewallResult]:
    engine = FirewallEngine()
    results: list[FirewallResult] = []
    rows: list[dict[str, Any]] = []

    for scenario in build_scenarios():
        session_context: dict[str, object] = {}
        for idx, step in enumerate(scenario.steps, start=1):
            request = FirewallRequest(
                text=step.text,
                tool_call=ToolCall(name=step.tool_name, args=dict(step.tool_args)),
                actor=Actor(user_id=step.actor_user_id, role=step.actor_role),
                session_context=session_context,
            )
            result = engine.validate_action(request)
            session_context = dict(result.updated_session_context)
            results.append(result)
            rows.append(_row_dict(scenario, idx, step, result))

    if print_output:
        if as_json:
            for row in rows:
                payload = dict(row)
                if not debug:
                    payload.pop("session", None)
                    payload.pop("normalized", None)
                print(json.dumps(payload, ensure_ascii=False))
        else:
            _print_table(rows, debug=debug)

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Orthus MCP server guard demo")
    parser.add_argument("--debug", action="store_true", help="Print matched rules and session state")
    parser.add_argument("--json", action="store_true", help="Output JSON lines")
    args = parser.parse_args(argv)

    run_demo(debug=args.debug, as_json=args.json, print_output=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
