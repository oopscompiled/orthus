from __future__ import annotations

from api.engine.cerber import CERBERScorer
from api.engine.decision.models import DecisionResult


def _decision(
    *,
    decision: str,
    risk: float,
    reason_codes: list[str] | None = None,
    matched_rules: list[str] | None = None,
) -> DecisionResult:
    return DecisionResult(
        decision=decision,  # type: ignore[arg-type]
        risk=risk,
        reason_codes=reason_codes or [],
        route="default",
        matched_rules=matched_rules or [],
        matched_policies=[],
        flags=[],
    )


def test_empty_session_allow_stays_low() -> None:
    scorer = CERBERScorer()
    result = scorer.score(_decision(decision="allow", risk=0.0), session_context=None)
    assert result.trajectory_risk <= 0.1
    assert result.risk_trend in {"stable", "rising", "falling"}


def test_prompt_injection_block_raises_risk() -> None:
    scorer = CERBERScorer()
    result = scorer.score(
        _decision(decision="block", risk=0.85, reason_codes=["instruction_override_attempt"]),
        session_context=None,
    )
    assert result.trajectory_risk > 0.18
    assert "recent_prompt_injection" in result.reason_codes


def test_repeated_blocks_raise_risk() -> None:
    scorer = CERBERScorer()
    session = None
    last = None
    for _ in range(3):
        last = scorer.score(_decision(decision="block", risk=0.8), session_context=session)
        session = last.updated_session_context
    assert last is not None
    assert "repeated_blocked_attempts" in last.reason_codes


def test_sensitive_tool_after_prompt_injection_raises_sequence_signal() -> None:
    scorer = CERBERScorer()
    first = scorer.score(
        _decision(decision="block", risk=0.8, reason_codes=["instruction_override_attempt"]),
        session_context=None,
    )
    second = scorer.score(
        _decision(decision="require_approval", risk=0.6),
        session_context=first.updated_session_context,
        tool_name="export_customer_data",
    )
    third = scorer.score(
        _decision(decision="require_approval", risk=0.6),
        session_context=second.updated_session_context,
        tool_name="refund_payment",
    )
    assert "sensitive_tool_sequence" in third.reason_codes


def test_high_velocity_raises_signal() -> None:
    scorer = CERBERScorer()
    session = None
    last = None
    for _ in range(8):
        last = scorer.score(_decision(decision="allow", risk=0.1), session_context=session)
        session = last.updated_session_context
    assert last is not None
    assert "high_velocity" in last.reason_codes


def test_risk_trend_rising_falling_stable() -> None:
    scorer = CERBERScorer()

    base = {
        "rolling_risk_score": 0.0,
        "blocked_count_10m": 2,
        "sensitive_actions_10m": 1,
        "velocity_1m": 0,
        "recent_reason_codes": [],
        "risk_trend": "stable",
    }
    rising = scorer.score(
        _decision(decision="block", risk=1.0, reason_codes=["instruction_override_attempt"]),
        session_context=base,
    )
    assert rising.risk_trend == "rising"

    high = dict(rising.updated_session_context)
    high["rolling_risk_score"] = 0.9
    falling = scorer.score(_decision(decision="allow", risk=0.0), session_context=high)
    assert falling.risk_trend in {"falling", "stable"}

    stable_context = {
        "rolling_risk_score": 0.1,
        "blocked_count_10m": 0,
        "sensitive_actions_10m": 0,
        "velocity_1m": 0,
        "recent_reason_codes": [],
        "risk_trend": "stable",
    }
    stable = scorer.score(_decision(decision="allow", risk=0.0), session_context=stable_context)
    assert stable.risk_trend == "stable"


def test_updated_context_is_serializable_dict() -> None:
    scorer = CERBERScorer()
    result = scorer.score(_decision(decision="allow", risk=0.1), session_context={})
    ctx = result.updated_session_context
    assert isinstance(ctx, dict)
    assert isinstance(ctx.get("recent_reason_codes"), list)


def test_mcp_session_hijack_sequence_raises_risk_and_reason() -> None:
    scorer = CERBERScorer()
    session = {}

    partial = scorer.score(
        _decision(decision="log_only", risk=0.56, matched_rules=["mcp_session.partial_handshake"]),
        session_context=session,
        tool_name="partial_subscribe",
        tool_args={"uri": "file:///shared/", "complete_handshake": False},
        actor={"user_id": "u1"},
    )

    takeover = scorer.score(
        _decision(decision="require_approval", risk=0.74, matched_rules=["mcp_session.takeover_pending_subscription"]),
        session_context=partial.updated_session_context,
        tool_name="resources/subscribe",
        tool_args={"uri": "file:///shared/", "takeover_pending": True},
        actor={"user_id": "u1"},
    )

    complete = scorer.score(
        _decision(decision="allow", risk=0.12),
        session_context=takeover.updated_session_context,
        tool_name="complete_handshake",
        tool_args={"session_id": "u1"},
        actor={"user_id": "u1"},
    )

    corruption = scorer.score(
        _decision(
            decision="require_approval",
            risk=0.78,
            reason_codes=["subscription_state_corruption"],
            matched_rules=["mcp_session.subscription_state_corruption"],
        ),
        session_context=complete.updated_session_context,
        tool_name="corrupt_subscription",
        tool_args={"uri": "file:///shared/", "payload": "malicious"},
        actor={"user_id": "u1"},
    )

    assert "session_hijack_sequence" in corruption.reason_codes
    assert "rising_session_risk" in corruption.reason_codes
    assert corruption.trajectory_risk >= 0.3
