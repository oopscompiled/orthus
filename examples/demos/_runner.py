"""Shared runner for small Orthus demo packages."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, ToolCall


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_demo(demo_dir: Path, *, as_json: bool = False, print_output: bool = True) -> dict[str, Any]:
    event = _load_json(demo_dir / "event.json")
    expected = _load_json(demo_dir / "expected_decision.json")
    tool_call = event["tool_call"]
    actor = event.get("actor", {})

    result = FirewallEngine().validate_action(
        FirewallRequest(
            text=event.get("text"),
            tool_call=ToolCall(
                name=tool_call["name"],
                args=dict(tool_call.get("args") or {}),
                description=tool_call.get("description"),
                result=tool_call.get("result"),
            ),
            actor=Actor(user_id=actor.get("user_id"), role=actor.get("role")),
            session_context=dict(event.get("session_context") or {}),
        )
    )

    decision_in = set(expected.get("decision_in") or [expected.get("decision")])
    must_reason_codes = set(expected.get("must_reason_codes") or [])
    passed = result.decision in decision_in and must_reason_codes.issubset(set(result.reason_codes))

    row = {
        "id": event["id"],
        "title": event["title"],
        "tool": tool_call["name"],
        "decision": result.decision,
        "risk": result.risk,
        "reason_codes": result.reason_codes,
        "expected": expected,
        "passed": passed,
    }

    if print_output:
        if as_json:
            print(json.dumps(row, ensure_ascii=False))
        else:
            print(event["title"])
            print(f"tool: {row['tool']}")
            print(f"decision: {row['decision']} risk={row['risk']:.2f}")
            print("reason_codes:", ", ".join(row["reason_codes"]) or "-")
            print("expected:", expected)
            print("passed:", passed)
    return row
