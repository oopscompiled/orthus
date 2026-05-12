from __future__ import annotations

from collections.abc import Iterable

from api.engine.normalizer.models import NormalizationResult
from api.engine.policy.engine import PolicyDecision
from api.engine.rules.models import RuleMatch

from .models import DecisionResult

POLICY_RISK_MAP = {
    "critical": 0.95,
    "high": 0.80,
    "medium": 0.55,
    "low": 0.20,
    None: 0.0,
}


class DecisionEngine:
    @staticmethod
    def _dedupe_reason_codes(policy_codes: Iterable[str], rule_codes: Iterable[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for code in list(policy_codes) + list(rule_codes):
            if code and code not in seen:
                seen.add(code)
                out.append(code)
            if len(out) >= 10:
                break
        return out

    @staticmethod
    def _max_rule_risk(rule_matches: list[RuleMatch]) -> float:
        return max((float(r.risk) for r in rule_matches), default=0.0)

    @staticmethod
    def _policy_risk(policy_decision: PolicyDecision | None) -> float:
        if not policy_decision:
            return 0.0
        level = (policy_decision.risk_level or "").lower() or None
        if level in POLICY_RISK_MAP:
            return POLICY_RISK_MAP[level]
        for code in policy_decision.reason_codes:
            if code.startswith("policy_risk_"):
                mapped = code.removeprefix("policy_risk_").lower()
                return POLICY_RISK_MAP.get(mapped, 0.0)
        return 0.0

    @staticmethod
    def _normalization_risk(normalization: NormalizationResult | None) -> float:
        # Placeholder for future explicit normalizer risk signal.
        return 0.0 if normalization is None else 0.0

    def decide(
        self,
        normalization: NormalizationResult | None,
        rule_matches: list[RuleMatch],
        policy_decision: PolicyDecision | None,
    ) -> DecisionResult:
        matched_rules = [m.rule_id for m in rule_matches]
        matched_policies = list(policy_decision.matched_policies) if policy_decision else []
        policy_codes = list(policy_decision.reason_codes) if policy_decision else []
        rule_codes = [code for m in rule_matches for code in m.reason_codes]

        policy_risk = self._policy_risk(policy_decision)
        max_rule_risk = self._max_rule_risk(rule_matches)
        normalization_risk = self._normalization_risk(normalization)
        risk = max(policy_risk, max_rule_risk, normalization_risk)

        has_policy = bool(policy_decision and policy_decision.decision)
        has_rules = bool(rule_matches)
        route = "combined" if has_policy and has_rules else "policy" if has_policy else "rules" if has_rules else "default"

        policy_is_block = bool(policy_decision and policy_decision.decision == "block")
        high_block_rule = any(
            m.decision_hint == "block" and m.severity in {"high", "critical"}
            for m in rule_matches
        )

        if policy_is_block:
            return DecisionResult(
                decision="block",
                risk=risk,
                reason_codes=self._dedupe_reason_codes(policy_codes, rule_codes),
                route=route,
                matched_rules=matched_rules,
                matched_policies=matched_policies,
                flags=["policy_block"],
            )

        if high_block_rule:
            return DecisionResult(
                decision="block",
                risk=risk,
                reason_codes=self._dedupe_reason_codes(policy_codes, rule_codes),
                route=route,
                matched_rules=matched_rules,
                matched_policies=matched_policies,
                flags=["high_risk_rule"],
            )

        if policy_decision and policy_decision.decision == "require_approval":
            return DecisionResult(
                decision="require_approval",
                risk=risk,
                reason_codes=self._dedupe_reason_codes(policy_codes, rule_codes),
                route=route,
                matched_rules=matched_rules,
                matched_policies=matched_policies,
            )

        medium_or_approval_rule = any(
            m.decision_hint == "require_approval" or m.severity == "medium"
            for m in rule_matches
        )
        if medium_or_approval_rule:
            return DecisionResult(
                decision="require_approval",
                risk=risk,
                reason_codes=self._dedupe_reason_codes(policy_codes, rule_codes),
                route=route,
                matched_rules=matched_rules,
                matched_policies=matched_policies,
            )

        if policy_decision and policy_decision.decision == "log_only":
            return DecisionResult(
                decision="log_only",
                risk=risk,
                reason_codes=self._dedupe_reason_codes(policy_codes, rule_codes),
                route=route,
                matched_rules=matched_rules,
                matched_policies=matched_policies,
            )

        low_or_log_rule = any(
            m.decision_hint == "log_only" or m.severity == "low"
            for m in rule_matches
        )
        if low_or_log_rule:
            return DecisionResult(
                decision="log_only",
                risk=risk,
                reason_codes=self._dedupe_reason_codes(policy_codes, rule_codes),
                route=route,
                matched_rules=matched_rules,
                matched_policies=matched_policies,
            )

        if rule_matches and all(m.severity == "low" for m in rule_matches) and not (policy_decision and policy_decision.decision):
            return DecisionResult(
                decision="log_only",
                risk=risk,
                reason_codes=self._dedupe_reason_codes(policy_codes, rule_codes),
                route=route,
                matched_rules=matched_rules,
                matched_policies=matched_policies,
            )

        return DecisionResult(
            decision="allow",
            risk=0.0,
            reason_codes=[],
            route="default",
            matched_rules=matched_rules,
            matched_policies=matched_policies,
            flags=[],
        )
