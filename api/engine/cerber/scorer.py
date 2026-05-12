"""CERBER deterministic session trajectory scorer."""

from __future__ import annotations

from typing import Any

from api.engine.decision.models import DecisionResult

from .config import (
    FALLING_DELTA,
    HIGH_VELOCITY_THRESHOLD,
    RECENT_REASON_CODES_LIMIT,
    RISING_DELTA,
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


class CERBERScorer:
    def __init__(self, *, sensitive_tools: set[str] | None = None) -> None:
        self.sensitive_tools = sensitive_tools or set(SENSITIVE_TOOLS)

    @staticmethod
    def _append_reason_once(reason_codes: list[str], value: str) -> None:
        if value not in reason_codes:
            reason_codes.append(value)

    @staticmethod
    def _merge_recent_reason_codes(previous: list[str], current: list[str]) -> list[str]:
        merged = list(previous)
        for code in current:
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
        actor: dict[str, Any] | None = None,  # reserved for future deterministic role anomaly checks
    ) -> CERBERResult:
        del actor

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

        recent_prompt_injection = 1.0 if any(
            (
                "instruction_override" in code
                or "prompt_injection" in code
                or "jailbreak" in code
            )
            for code in session.recent_reason_codes
        ) else 0.0

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
        if trend == "rising":
            self._append_reason_once(output_codes, "rising_session_risk")
        if session.blocked_count_10m >= 2:
            self._append_reason_once(output_codes, "repeated_blocked_attempts")
        if session.sensitive_actions_10m >= 2 and recent_prompt_injection > 0:
            self._append_reason_once(output_codes, "sensitive_tool_sequence")
        if session.velocity_1m >= HIGH_VELOCITY_THRESHOLD:
            self._append_reason_once(output_codes, "high_velocity")
        if recent_prompt_injection > 0:
            self._append_reason_once(output_codes, "recent_prompt_injection")

        return CERBERResult(
            trajectory_risk=rolling,
            risk_trend=trend,
            reason_codes=output_codes,
            updated_session_context=session.to_dict(),
        )
