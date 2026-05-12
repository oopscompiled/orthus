from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from api.engine.cerber import CERBERScorer
from api.engine.decision import DecisionEngine
from api.engine.normalizer import normalize_text
from api.engine.policy import PolicyEngine
from api.engine.rules import RulesEngine, load_builtin_basic_rules

from .models import Actor, FirewallRequest, FirewallResult, ToolCall

CERBER_UPGRADE_THRESHOLD = 0.75
ELEVATED_RISK_LOG_ONLY_THRESHOLD = 0.65


class FirewallEngine:
    def __init__(
        self,
        *,
        rules_engine: RulesEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        decision_engine: DecisionEngine | None = None,
        cerber_scorer: CERBERScorer | None = None,
    ) -> None:
        self.rules_engine = rules_engine or RulesEngine(load_builtin_basic_rules())

        if policy_engine is not None:
            self.policy_engine = policy_engine
        else:
            default_policy = Path("policy/default.yaml")
            self.policy_engine = PolicyEngine.from_yaml(str(default_policy)) if default_policy.exists() else None

        self.decision_engine = decision_engine or DecisionEngine()
        self.cerber_scorer = cerber_scorer or CERBERScorer()

    @staticmethod
    def _dedupe(items: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in items:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out

    @staticmethod
    def _actor_to_dict(actor: Actor | None) -> dict[str, object]:
        if not actor:
            return {}
        out: dict[str, object] = {}
        if actor.user_id is not None:
            out["user_id"] = actor.user_id
        if actor.role is not None:
            out["role"] = actor.role
        return out

    @staticmethod
    def _build_scan_text(request: FirewallRequest) -> str:
        parts: list[str] = []

        if request.text:
            parts.append(request.text)

        tc: ToolCall | None = request.tool_call
        if tc:
            parts.append(tc.name)
            if tc.description:
                parts.append(tc.description)
            if tc.args:
                parts.append(json.dumps(tc.args, sort_keys=True, ensure_ascii=False, default=str))
            if tc.result:
                parts.append(tc.result)

        return "\n".join(part for part in parts if part)

    def validate_action(self, request: FirewallRequest) -> FirewallResult:
        return self._run_pipeline(request, mode="validate_action")

    def scan_tool_call(self, request: FirewallRequest) -> FirewallResult:
        return self._run_pipeline(request, mode="scan_tool_call")

    def _run_pipeline(self, request: FirewallRequest, *, mode: str) -> FirewallResult:
        start = time.perf_counter()

        routes: list[str] = []
        scan_text = self._build_scan_text(request)

        normalization = normalize_text(scan_text)
        routes.append("normalizer")

        rule_matches = self.rules_engine.scan(normalization)
        routes.append("rules")

        actor_dict = self._actor_to_dict(request.actor)
        session_context = dict(request.session_context or {})

        policy_decision = None
        if request.tool_call and self.policy_engine is not None:
            policy_decision = self.policy_engine.evaluate(
                request.tool_call.name,
                args=dict(request.tool_call.args),
                actor=actor_dict,
                session=session_context,
            )
            routes.append("policy")

        preliminary = self.decision_engine.decide(
            normalization=normalization,
            rule_matches=rule_matches,
            policy_decision=policy_decision,
        )

        cerber = self.cerber_scorer.score(
            decision_result=preliminary,
            session_context=session_context,
            tool_name=request.tool_call.name if request.tool_call else None,
            actor=actor_dict,
        )
        routes.append("cerber")

        # TODO: V1 applies CERBER as a post-decision upgrade.
        # Later DecisionEngine should consume CERBER as a first-class signal.
        final_decision = preliminary.decision
        final_route = preliminary.route
        risk = max(preliminary.risk, cerber.trajectory_risk)

        reason_codes = self._dedupe(preliminary.reason_codes + cerber.reason_codes)

        if final_decision == "allow" and risk >= ELEVATED_RISK_LOG_ONLY_THRESHOLD:
            final_decision = "log_only"
            final_route = "fast_path"
            reason_codes = self._dedupe(reason_codes + ["elevated_session_risk"])

        if preliminary.decision in {"allow", "log_only"} and cerber.trajectory_risk >= CERBER_UPGRADE_THRESHOLD:
            final_decision = "require_approval"
            final_route = "fast_path"
            reason_codes = self._dedupe(reason_codes + ["rising_session_risk"])
        matched_rules = self._dedupe([m.rule_id for m in rule_matches])

        latency_ms = (time.perf_counter() - start) * 1000.0

        return FirewallResult(
            decision=final_decision,
            risk=risk,
            reason_codes=reason_codes,
            route=final_route,
            routes=routes,
            matched_rules=matched_rules,
            flags=list(normalization.flags),
            # TODO: production API should hide debug fields (normalized/matched_rules)
            # unless debug=true, because they may contain sensitive text.
            normalized=normalization.normalized,
            updated_session_context=cerber.updated_session_context,
            latency_ms=max(0.0, latency_ms),
        )
