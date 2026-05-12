from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ToolCall:
    name: str
    args: dict[str, object] = field(default_factory=dict)
    description: str | None = None
    result: str | None = None


@dataclass(slots=True)
class Actor:
    user_id: str | None = None
    role: str | None = None


@dataclass(slots=True)
class FirewallRequest:
    text: str | None = None
    tool_call: ToolCall | None = None
    actor: Actor | None = None
    session_context: dict[str, object] | None = None


@dataclass(slots=True)
class FirewallResult:
    decision: str
    risk: float
    reason_codes: list[str]
    route: str
    routes: list[str]
    matched_rules: list[str]
    flags: list[str]
    normalized: str
    updated_session_context: dict[str, object]
    latency_ms: float
