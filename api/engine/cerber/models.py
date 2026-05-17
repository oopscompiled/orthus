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
