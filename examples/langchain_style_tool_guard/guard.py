"""Generic before-tool hook pattern for LangChain-style agent runtimes.

This example intentionally avoids importing LangChain. It demonstrates the
framework-agnostic hook shape: before executing a tool, build an Orthus action
event and branch on the decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, FirewallResult, ToolCall


@dataclass(slots=True)
class ToolExecutionDecision:
    result: FirewallResult

    @property
    def may_execute(self) -> bool:
        return self.result.decision in {"allow", "log_only"}

    @property
    def needs_approval(self) -> bool:
        return self.result.decision == "require_approval"

    @property
    def blocked(self) -> bool:
        return self.result.decision == "block"


def before_tool_execution(
    tool_name: str,
    args: dict[str, Any],
    context: dict[str, Any],
    *,
    firewall: FirewallEngine | None = None,
) -> ToolExecutionDecision:
    """Validate a proposed tool execution before a framework invokes it."""
    engine = firewall or FirewallEngine()
    actor_data = context.get("actor") or {}
    source_refs = context.get("source_refs")
    tool_args = dict(args)
    if source_refs is not None:
        tool_args.setdefault("source_refs", source_refs)

    result = engine.validate_action(
        FirewallRequest(
            text=context.get("text"),
            tool_call=ToolCall(name=tool_name, args=tool_args),
            actor=Actor(user_id=actor_data.get("user_id"), role=actor_data.get("role")),
            session_context=dict(context.get("session_context") or {}),
        )
    )
    return ToolExecutionDecision(result=result)


def execute_with_guard(
    tool_name: str,
    args: dict[str, Any],
    context: dict[str, Any],
    tool_registry: dict[str, Any],
    *,
    firewall: FirewallEngine | None = None,
) -> Any:
    decision = before_tool_execution(tool_name, args, context, firewall=firewall)
    if decision.blocked:
        return {"status": "blocked", "reason_codes": decision.result.reason_codes}
    if decision.needs_approval:
        return {"status": "approval_required", "reason_codes": decision.result.reason_codes}
    return tool_registry[tool_name](**args)
