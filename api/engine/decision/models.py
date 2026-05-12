from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Decision = Literal["allow", "block", "redact", "require_approval", "sandbox", "log_only"]
Route = Literal["rules", "policy", "combined", "default"]


@dataclass(slots=True)
class DecisionResult:
    decision: Decision
    risk: float
    reason_codes: list[str] = field(default_factory=list)
    route: Route = "default"
    matched_rules: list[str] = field(default_factory=list)
    matched_policies: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
