from __future__ import annotations

import json
from pathlib import Path

from api.engine.decision.engine import DecisionEngine
from api.engine.policy.engine import PolicyDecision
from api.engine.rules.models import RuleMatch


def _rule_match(item: dict) -> RuleMatch:
    return RuleMatch(
        rule_id=item["id"],
        pack="fixture",
        severity=item["severity"],
        risk=float(item["risk"]),
        decision_hint=item["decision_hint"],
        reason_codes=list(item.get("reason_codes", [])),
        matched_field="normalized",
        matched_text="fixture",
        pattern="fixture",
        tags=[],
    )


def _load_cases() -> list[dict]:
    path = Path("tests/fixtures/decision/decision_cases.jsonl")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_decision_corpus() -> None:
    engine = DecisionEngine()
    for case in _load_cases():
        rules = [_rule_match(item) for item in case.get("rule_matches", [])]
        raw_policy = case.get("policy_decision")
        policy = None
        if isinstance(raw_policy, dict):
            policy = PolicyDecision(
                decision=raw_policy.get("decision"),
                reason_codes=list(raw_policy.get("reason_codes", [])),
                matched_policies=list(raw_policy.get("matched_policies", [])),
                risk_level=raw_policy.get("risk_level"),
            )

        result = engine.decide(None, rules, policy)
        assert result.decision == case["expect_decision"], case.get("note", "decision mismatch")
        if "expect_route" in case:
            assert result.route == case["expect_route"], case.get("note", "route mismatch")
        if "expect_risk" in case:
            assert result.risk == float(case["expect_risk"]), case.get("note", "risk mismatch")
