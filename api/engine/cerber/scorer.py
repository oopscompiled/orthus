"""CERBER deterministic session trajectory scorer."""

from __future__ import annotations

from typing import Any

from api.engine.decision.models import DecisionResult

from .config import (
    FALLING_DELTA,
    HIGH_VELOCITY_THRESHOLD,
    LOW_IMPACT_REASON_CODES,
    MCP_CHAIN_RISK_BOOST,
    MCP_CHAIN_TTL_STEPS,
    RECENT_REASON_CODES_LIMIT,
    RISING_DELTA,
    SECURITY_REASON_CODES,
    SECURITY_RISK_MIN,
    SENSITIVE_TOOLS,
    SMOOTHING_ALPHA,
    WEIGHTS,
)
from .models import CERBERResult, SessionContext


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _extract_first_uri(value: Any) -> str:
    uri_keys = {"uri", "path", "resource", "target", "source", "file", "filename"}
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in uri_keys and nested is not None:
                return str(nested).lower()
            found = _extract_first_uri(nested)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _extract_first_uri(item)
            if found:
                return found
    return ""


class CERBERScorer:
    def __init__(self, *, sensitive_tools: set[str] | None = None) -> None:
        self.sensitive_tools = sensitive_tools or set(SENSITIVE_TOOLS)

    @staticmethod
    def _append_reason_once(reason_codes: list[str], value: str) -> None:
        if value not in reason_codes:
            reason_codes.append(value)

    @staticmethod
    def _merge_recent_reason_codes(previous: list[str], current: list[str]) -> list[str]:
        merged = [code for code in previous if code not in LOW_IMPACT_REASON_CODES]
        for code in current:
            if code in LOW_IMPACT_REASON_CODES:
                continue
            if code not in merged:
                merged.append(code)
        if len(merged) > RECENT_REASON_CODES_LIMIT:
            merged = merged[-RECENT_REASON_CODES_LIMIT:]
        return merged

    def score(
        self,
        decision_result: DecisionResult,
        session_context: dict[str, Any] | SessionContext | None = None,
        *,
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        actor: dict[str, Any] | None = None,  # reserved for future deterministic role anomaly checks
    ) -> CERBERResult:
        actor = actor or {}

        session = SessionContext.from_input(session_context)
        previous_risk = float(session.rolling_risk_score)

        session.velocity_1m = max(0, int(session.velocity_1m) + 1)

        if decision_result.decision == "block":
            session.blocked_count_10m = int(session.blocked_count_10m) + 1
        else:
            session.blocked_count_10m = max(0, int(session.blocked_count_10m) - 1)

        if tool_name and tool_name in self.sensitive_tools:
            session.sensitive_actions_10m = int(session.sensitive_actions_10m) + 1
        else:
            session.sensitive_actions_10m = max(0, int(session.sensitive_actions_10m) - 1)

        session.recent_reason_codes = self._merge_recent_reason_codes(
            session.recent_reason_codes,
            decision_result.reason_codes,
        )

        # MCP lifecycle/session-hijack chain detector:
        # partial_handshake -> takeover_pending_subscription -> complete_handshake -> subscription_state_corruption
        matched_rules = set(decision_result.matched_rules)
        user_id = str(actor.get("user_id", ""))
        current_uri = _extract_first_uri(tool_args or {})
        session.mcp_chain_age_steps = int(session.mcp_chain_age_steps) + 1
        if session.mcp_chain_age_steps > MCP_CHAIN_TTL_STEPS:
            session.mcp_chain_stage = 0
            session.mcp_chain_user_id = ""
            session.mcp_chain_uri = ""
            session.mcp_chain_age_steps = 0

        mcp_chain_hit = False
        if "mcp_session.partial_handshake" in matched_rules:
            session.mcp_chain_stage = 1
            session.mcp_chain_user_id = user_id
            session.mcp_chain_uri = current_uri
            session.mcp_chain_age_steps = 0
        elif "mcp_session.takeover_pending_subscription" in matched_rules:
            same_actor = (not session.mcp_chain_user_id) or session.mcp_chain_user_id == user_id
            same_uri = (not session.mcp_chain_uri) or (current_uri and session.mcp_chain_uri == current_uri)
            if session.mcp_chain_stage >= 1 and same_actor and same_uri:
                session.mcp_chain_stage = 2
                session.mcp_chain_age_steps = 0
        elif tool_name == "complete_handshake":
            same_actor = (not session.mcp_chain_user_id) or session.mcp_chain_user_id == user_id
            if session.mcp_chain_stage >= 2 and same_actor:
                session.mcp_chain_stage = 3
                session.mcp_chain_age_steps = 0
        elif "mcp_session.subscription_state_corruption" in matched_rules:
            same_actor = (not session.mcp_chain_user_id) or session.mcp_chain_user_id == user_id
            if session.mcp_chain_stage >= 2 and same_actor:
                mcp_chain_hit = True
                session.mcp_chain_stage = 4
                session.mcp_chain_age_steps = 0

        current_security_hit = any(code in SECURITY_REASON_CODES for code in decision_result.reason_codes)
        recent_prompt_injection = 1.0 if any(code in SECURITY_REASON_CODES for code in session.recent_reason_codes) else 0.0

        blocked_score = _clamp01(session.blocked_count_10m / 3.0)
        sensitive_score = _clamp01(session.sensitive_actions_10m / 3.0)
        velocity_score = _clamp01(session.velocity_1m / float(HIGH_VELOCITY_THRESHOLD))
        decision_risk = _clamp01(float(decision_result.risk))

        instant_risk = (
            WEIGHTS["decision_risk"] * decision_risk
            + WEIGHTS["blocked_attempts"] * blocked_score
            + WEIGHTS["sensitive_actions"] * sensitive_score
            + WEIGHTS["velocity"] * velocity_score
            + WEIGHTS["prompt_injection_recent"] * recent_prompt_injection
        )
        if mcp_chain_hit:
            instant_risk = _clamp01(instant_risk + MCP_CHAIN_RISK_BOOST)

        rolling = ((1.0 - SMOOTHING_ALPHA) * previous_risk) + (SMOOTHING_ALPHA * instant_risk)
        rolling = round(_clamp01(rolling), 4)
        session.rolling_risk_score = rolling

        delta = rolling - previous_risk
        if delta >= RISING_DELTA:
            trend = "rising"
        elif delta <= FALLING_DELTA:
            trend = "falling"
        else:
            trend = "stable"
        session.risk_trend = trend

        output_codes: list[str] = []
        if trend == "rising" and decision_risk >= SECURITY_RISK_MIN and current_security_hit:
            self._append_reason_once(output_codes, "rising_session_risk")
        if session.blocked_count_10m >= 2:
            self._append_reason_once(output_codes, "repeated_blocked_attempts")
        if session.sensitive_actions_10m >= 2 and recent_prompt_injection > 0:
            self._append_reason_once(output_codes, "sensitive_tool_sequence")
        if session.velocity_1m >= HIGH_VELOCITY_THRESHOLD:
            self._append_reason_once(output_codes, "high_velocity")
        if recent_prompt_injection > 0 and current_security_hit:
            self._append_reason_once(output_codes, "recent_prompt_injection")
        if mcp_chain_hit:
            self._append_reason_once(output_codes, "session_hijack_sequence")
            self._append_reason_once(output_codes, "rising_session_risk")

        return CERBERResult(
            trajectory_risk=rolling,
            risk_trend=trend,
            reason_codes=output_codes,
            updated_session_context=session.to_dict(),
        )
