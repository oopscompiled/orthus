"""CERBER session models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

RiskTrend = Literal["stable", "rising", "falling"]


@dataclass(slots=True)
class SessionContext:
    session_id: str = ""
    rolling_risk_score: float = 0.0
    risk_trend: RiskTrend = "stable"
    blocked_count_10m: int = 0
    sensitive_actions_10m: int = 0
    velocity_1m: int = 0
    recent_reason_codes: list[str] = field(default_factory=list)
    mcp_chain_stage: int = 0
    mcp_chain_user_id: str = ""
    mcp_chain_uri: str = ""
    mcp_chain_age_steps: int = 0
    recent_partial_subscriptions: list[str] = field(default_factory=list)
    recent_unsubscribed_ids: list[str] = field(default_factory=list)
    last_protocol_version: str = ""
    last_protocol_capabilities_had_security: bool = False
    subscription_chain_seed: bool = False
    recent_payment_attempt_signatures: list[str] = field(default_factory=list)
    payment_verification_attempt_count: int = 0
    last_trusted_intent_event_id: str = ""
    last_trusted_intent_action: str = ""
    trusted_intent_age_steps: int = 0
    recent_sensitive_markers: list[str] = field(default_factory=list)
    recent_oracle_signatures: list[str] = field(default_factory=list)
    oracle_iteration_count: int = 0
    current_allowed_tool_scope: list[str] = field(default_factory=list)
    current_expected_action_kind: str = ""
    recent_untrusted_plan_directives: list[str] = field(default_factory=list)
    pending_mcp_request_signatures: list[str] = field(default_factory=list)
    completed_mcp_request_signatures: list[str] = field(default_factory=list)
    canceled_mcp_request_signatures: list[str] = field(default_factory=list)
    recent_mcp_trace_violation_markers: list[str] = field(default_factory=list)
    recent_written_artifacts: list[str] = field(default_factory=list)
    recent_cross_protocol_directives: list[str] = field(default_factory=list)

    @classmethod
    def from_input(cls, value: dict | "SessionContext" | None) -> "SessionContext":
        if isinstance(value, SessionContext):
            return value
        if isinstance(value, dict):
            return cls(
                session_id=str(value.get("session_id", "")),
                rolling_risk_score=float(value.get("rolling_risk_score", 0.0)),
                risk_trend=str(value.get("risk_trend", "stable")),  # type: ignore[arg-type]
                blocked_count_10m=int(value.get("blocked_count_10m", 0)),
                sensitive_actions_10m=int(value.get("sensitive_actions_10m", 0)),
                velocity_1m=int(value.get("velocity_1m", 0)),
                recent_reason_codes=[str(code) for code in value.get("recent_reason_codes", [])],
                mcp_chain_stage=int(value.get("mcp_chain_stage", 0)),
                mcp_chain_user_id=str(value.get("mcp_chain_user_id", "")),
                mcp_chain_uri=str(value.get("mcp_chain_uri", "")),
                mcp_chain_age_steps=int(value.get("mcp_chain_age_steps", 0)),
                recent_partial_subscriptions=[str(v) for v in value.get("recent_partial_subscriptions", [])],
                recent_unsubscribed_ids=[str(v) for v in value.get("recent_unsubscribed_ids", [])],
                last_protocol_version=str(value.get("last_protocol_version", "")),
                last_protocol_capabilities_had_security=bool(value.get("last_protocol_capabilities_had_security", False)),
                subscription_chain_seed=bool(value.get("subscription_chain_seed", False)),
                recent_payment_attempt_signatures=[str(v) for v in value.get("recent_payment_attempt_signatures", [])],
                payment_verification_attempt_count=int(value.get("payment_verification_attempt_count", 0)),
                last_trusted_intent_event_id=str(value.get("last_trusted_intent_event_id", "")),
                last_trusted_intent_action=str(value.get("last_trusted_intent_action", "")),
                trusted_intent_age_steps=int(value.get("trusted_intent_age_steps", 0)),
                recent_sensitive_markers=[str(v) for v in value.get("recent_sensitive_markers", [])],
                recent_oracle_signatures=[str(v) for v in value.get("recent_oracle_signatures", [])],
                oracle_iteration_count=int(value.get("oracle_iteration_count", 0)),
                current_allowed_tool_scope=[str(v) for v in value.get("current_allowed_tool_scope", [])],
                current_expected_action_kind=str(value.get("current_expected_action_kind", "")),
                recent_untrusted_plan_directives=[str(v) for v in value.get("recent_untrusted_plan_directives", [])],
                pending_mcp_request_signatures=[str(v) for v in value.get("pending_mcp_request_signatures", [])],
                completed_mcp_request_signatures=[str(v) for v in value.get("completed_mcp_request_signatures", [])],
                canceled_mcp_request_signatures=[str(v) for v in value.get("canceled_mcp_request_signatures", [])],
                recent_mcp_trace_violation_markers=[str(v) for v in value.get("recent_mcp_trace_violation_markers", [])],
                recent_written_artifacts=[str(v) for v in value.get("recent_written_artifacts", [])],
                recent_cross_protocol_directives=[str(v) for v in value.get("recent_cross_protocol_directives", [])],
            )
        return cls()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class CERBERResult:
    trajectory_risk: float
    risk_trend: RiskTrend
    reason_codes: list[str]
    updated_session_context: dict
