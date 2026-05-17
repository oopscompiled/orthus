from __future__ import annotations

import json
from pathlib import Path

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, ToolCall


CASES: list[dict] = []
for fixture_path in sorted(Path("tests/fixtures/pipeline").glob("*.jsonl")):
    for line in fixture_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            case = json.loads(line)
            case.setdefault("_fixture_file", fixture_path.name)
            CASES.append(case)


def _build_request(raw: dict) -> FirewallRequest:
    if "request" in raw and isinstance(raw["request"], dict):
        raw = raw["request"]
    tool_call_raw = raw.get("tool_call")
    actor_raw = raw.get("actor")
    tool_call = None
    if isinstance(tool_call_raw, dict):
        tool_name = str(tool_call_raw.get("name", ""))
        tool_args = dict(tool_call_raw.get("args") or {})
        for key, value in tool_call_raw.items():
            if key not in {"name", "args", "description", "result"}:
                tool_args[key] = value
        tool_call = ToolCall(
            name=tool_name,
            args=tool_args,
            description=tool_call_raw.get("description"),
            result=tool_call_raw.get("result"),
        )
    return FirewallRequest(
        text=raw.get("text"),
        tool_call=tool_call,
        actor=Actor(**actor_raw) if isinstance(actor_raw, dict) else None,
        session_context=raw.get("session_context"),
    )


def test_pipeline_corpus() -> None:
    engine = FirewallEngine()
    for case in CASES:
        tier = str(case.get("tier", "basic"))
        if tier in {"pro_candidate", "private_intel"} and "expect_basic" not in case:
            continue
        if "request" not in case:
            continue

        result = engine.validate_action(_build_request(case["request"]))
        expect = case.get("expect_basic") or case.get("expect", {})
        if not expect:
            continue

        if "decision_in" in expect:
            assert result.decision in set(expect["decision_in"]), case["id"]
        if "decision" in expect:
            assert result.decision == expect["decision"], case["id"]

        for rule_id in expect.get("must_match", []):
            assert rule_id in result.matched_rules, case["id"]
        for rule_id in expect.get("must_not_match", []):
            assert rule_id not in result.matched_rules, case["id"]

        for decision in expect.get("must_not_decision", []):
            assert result.decision != decision, case["id"]

        for reason in expect.get("must_not_reason_codes", []):
            assert reason not in result.reason_codes, case["id"]

        if "min_risk" in expect:
            assert result.risk >= float(expect["min_risk"]), case["id"]
        if "max_risk" in expect:
            assert result.risk <= float(expect["max_risk"]), case["id"]
