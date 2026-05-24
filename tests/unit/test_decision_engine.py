from __future__ import annotations

from api.engine.decision.engine import DecisionEngine
from api.engine.policy.engine import PolicyDecision
from api.engine.rules.models import RuleMatch


def _rule(
    rule_id: str,
    *,
    risk: float,
    decision_hint: str,
    severity: str,
    reason_codes: list[str],
) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        pack="test",
        severity=severity,
        risk=risk,
        decision_hint=decision_hint,
        reason_codes=reason_codes,
        matched_field="normalized",
        matched_text="x",
        pattern="x",
        tags=[],
    )


def test_policy_block_wins() -> None:
    engine = DecisionEngine()
    policy = PolicyDecision(decision="block", reason_codes=["policy_block_condition_matched"], matched_policies=["tools.x.block_if"], risk_level="high")
    result = engine.decide(normalization=None, rule_matches=[], policy_decision=policy)
    assert result.decision == "block"
    assert result.route == "policy"


def test_policy_require_approval_beats_rule_log_only() -> None:
    engine = DecisionEngine()
    policy = PolicyDecision(decision="require_approval", reason_codes=["policy_require_approval_always"], matched_policies=["tools.x.require_approval"], risk_level="high")
    rules = [_rule("prompt_injection.ignore_previous_soft", risk=0.35, decision_hint="log_only", severity="low", reason_codes=["instruction_override_soft"])]
    result = engine.decide(None, rules, policy)
    assert result.decision == "require_approval"


def test_high_severity_block_rule() -> None:
    engine = DecisionEngine()
    rules = [_rule("prompt_injection.ignore_previous", risk=0.85, decision_hint="block", severity="high", reason_codes=["instruction_override_attempt"])]
    result = engine.decide(None, rules, None)
    assert result.decision == "block"
    assert result.route == "rules"


def test_soft_rule_log_only() -> None:
    engine = DecisionEngine()
    rules = [_rule("prompt_injection.ignore_previous_soft", risk=0.35, decision_hint="log_only", severity="low", reason_codes=["instruction_override_soft"])]
    result = engine.decide(None, rules, None)
    assert result.decision == "log_only"


def test_no_matches_allow() -> None:
    engine = DecisionEngine()
    result = engine.decide(None, [], None)
    assert result.decision == "allow"
    assert result.risk == 0.0
    assert result.route == "default"


def test_reason_codes_deduplicated_ordered() -> None:
    engine = DecisionEngine()
    policy = PolicyDecision(decision="block", reason_codes=["code_a", "code_b"], matched_policies=["tools.x.block_if"], risk_level="critical")
    rules = [_rule("x", risk=0.5, decision_hint="log_only", severity="low", reason_codes=["code_b", "code_c"])]
    result = engine.decide(None, rules, policy)
    assert result.reason_codes == ["code_a", "code_b", "code_c"]


def test_matched_rules_contains_ids() -> None:
    engine = DecisionEngine()
    rules = [_rule("prompt_injection.end_anchor", risk=0.87, decision_hint="block", severity="high", reason_codes=["instruction_override_attempt"])]
    result = engine.decide(None, rules, None)
    assert "prompt_injection.end_anchor" in result.matched_rules


def test_risk_max_policy_rules() -> None:
    engine = DecisionEngine()
    policy = PolicyDecision(decision="require_approval", reason_codes=["policy_risk_medium"], matched_policies=["tools.x.require_approval"], risk_level="medium")
    rules = [_rule("x", risk=0.85, decision_hint="block", severity="high", reason_codes=["x"])]
    result = engine.decide(None, rules, policy)
    assert result.risk == 0.85


def test_route_combined_when_both_sources_match() -> None:
    engine = DecisionEngine()
    policy = PolicyDecision(decision="block", reason_codes=["policy_block_condition_matched"], matched_policies=["tools.x.block_if"], risk_level="critical")
    rules = [_rule("x", risk=0.85, decision_hint="block", severity="high", reason_codes=["instruction_override_attempt"])]
    result = engine.decide(None, rules, policy)
    assert result.route == "combined"
