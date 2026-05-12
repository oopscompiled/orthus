"""
CERBER - deterministic trajectory risk scorer.
Layer 4 in the decision pipeline.

Principle: one request may look normal, a sequence may look like an attack.

Formula:
  trajectory_risk =
    0.30 * recent_probe_score
  + 0.20 * blocked_attempts
  + 0.20 * sensitive_tool_count
  + 0.20 * velocity_score
  + 0.10 * role_anomaly

Input: compact session security state (stateless-first: client passes, API returns updated)
Output: trajectory_risk float + updated session state
"""

from dataclasses import dataclass, field


@dataclass
class SessionState:
    session_id: str = ""
    rolling_risk_score: float = 0.0
    risk_trend: str = "stable"  # stable | rising | falling
    recent_reason_codes: list[str] = field(default_factory=list)
    blocked_count_10m: int = 0
    sensitive_actions_10m: int = 0
    tool_probe_count: int = 0
    velocity_1m: int = 0
    velocity_10m: int = 0


@dataclass
class TrajectoryResult:
    trajectory_risk: float
    updated_session: SessionState
    contributing_factors: dict[str, float]


class CERBERScorer:
    WEIGHTS = {
        "recent_probe_score": 0.30,
        "blocked_attempts": 0.20,
        "sensitive_tool_count": 0.20,
        "velocity_score": 0.20,
        "role_anomaly": 0.10,
    }

    def score(self, session: SessionState, current_reason_codes: list[str]) -> TrajectoryResult:
        # TODO: implement scoring formula
        raise NotImplementedError("CERBERScorer.score() not yet implemented")
