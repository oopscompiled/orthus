"""Small dependency-free wrapper for guarding OpenAI-style tool calls.

The example intentionally does not import the OpenAI SDK. It demonstrates the
pre-execution pattern integrations should use: normalize a proposed tool call,
ask Orthus for a decision, then execute only if the decision allows it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, FirewallResult, ToolCall


@dataclass(slots=True)
class GuardedToolDecision:
    result: FirewallResult

    @property
    def decision(self) -> str:
        return self.result.decision

    @property
    def blocked(self) -> bool:
        return self.result.decision == "block"

    @property
    def requires_approval(self) -> bool:
        return self.result.decision == "require_approval"

    @property
    def may_execute(self) -> bool:
        return self.result.decision in {"allow", "log_only"}

    def explain(self) -> str:
        reasons = ", ".join(self.result.reason_codes) or "no reason codes"
        return f"Orthus decision={self.result.decision} risk={self.result.risk:.2f} reason_codes={reasons}"


def validate_tool_call(
    *,
    tool_name: str,
    tool_args: dict[str, Any],
    actor: dict[str, str] | Actor,
    text: str | None = None,
    source_refs: list[dict[str, Any]] | None = None,
    session_context: dict[str, Any] | None = None,
    firewall: FirewallEngine | None = None,
) -> GuardedToolDecision:
    """Validate a proposed tool call before application code executes it."""
    engine = firewall or FirewallEngine()
    actor_obj = actor if isinstance(actor, Actor) else Actor(user_id=actor.get("user_id"), role=actor.get("role"))
    args = dict(tool_args)
    if source_refs is not None:
        args.setdefault("source_refs", source_refs)

    result = engine.validate_action(
        FirewallRequest(
            text=text,
            tool_call=ToolCall(name=tool_name, args=args),
            actor=actor_obj,
            session_context=dict(session_context or {}),
        )
    )
    return GuardedToolDecision(result=result)


def execute_if_allowed(decision: GuardedToolDecision, tool_name: str, tool_args: dict[str, Any]) -> str:
    """Demo executor: real integrations would call their actual tool here."""
    if decision.blocked:
        return f"blocked: {decision.explain()}"
    if decision.requires_approval:
        return f"approval_required: {decision.explain()}"
    return f"executed: {tool_name}({tool_args})"
