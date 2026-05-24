from __future__ import annotations

import json
from pathlib import Path

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, ToolCall

SEQUENCES: list[dict] = []
for fixture_path in sorted(Path("tests/fixtures/pipeline_stateful").glob("*.jsonl")):
    for line in fixture_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            seq = json.loads(line)
            seq.setdefault("_fixture_file", fixture_path.name)
            SEQUENCES.append(seq)


def _build_request(step: dict, session_context: dict[str, object]) -> FirewallRequest:
    tool_call_raw = step.get("tool_call") or {}
    actor_raw = step.get("actor") or {}
    return FirewallRequest(
        text=step.get("text"),
        tool_call=ToolCall(
            name=str(tool_call_raw.get("name", "")),
            args=dict(tool_call_raw.get("args") or {}),
            description=tool_call_raw.get("description"),
            result=tool_call_raw.get("result"),
        ) if tool_call_raw else None,
        actor=Actor(**actor_raw) if actor_raw else None,
        session_context=session_context,
    )


def _assert_expect(result, expect: dict, seq_id: str, step_idx: int) -> None:
    marker = f"{seq_id}#step{step_idx}"

    if "decision" in expect:
        assert result.decision == expect["decision"], marker
    if "decision_in" in expect:
        assert result.decision in set(expect["decision_in"]), marker

    for rule_id in expect.get("must_match", []):
        assert rule_id in result.matched_rules, marker
    for rule_id in expect.get("must_not_match", []):
        assert rule_id not in result.matched_rules, marker

    for reason in expect.get("must_reason_codes", []):
        assert reason in result.reason_codes, marker
    for reason in expect.get("must_not_reason_codes", []):
        assert reason not in result.reason_codes, marker

    if "min_risk" in expect:
        assert result.risk >= float(expect["min_risk"]), marker
    if "max_risk" in expect:
        assert result.risk <= float(expect["max_risk"]), marker


def test_pipeline_stateful_corpus() -> None:
    for sequence in SEQUENCES:
        engine = FirewallEngine()
        session_context: dict[str, object] = {}

        for idx, step in enumerate(sequence.get("steps", []), start=1):
            request = _build_request(step, session_context)
            result = engine.validate_action(request)
            session_context = dict(result.updated_session_context)

            expect = step.get("expect", {})
            if expect:
                _assert_expect(result, expect, sequence["id"], idx)
