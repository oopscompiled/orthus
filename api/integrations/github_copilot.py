"""Dependency-free GitHub Copilot SDK pre-tool-use guard adapter.

This module intentionally does not import the GitHub Copilot SDK. It provides
the hook shape Orthus integrators can pass to Copilot SDK runtimes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, FirewallResult, ToolCall


def _get_value(source: Any, *names: str) -> Any:
    if source is None:
        return None
    for name in names:
        if isinstance(source, Mapping) and name in source:
            return source[name]
        if hasattr(source, name):
            return getattr(source, name)
    return None


def _as_dict(value: Any) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _normalize_actor(actor: Actor | Mapping[str, object] | None) -> Actor | None:
    if actor is None:
        return None
    if isinstance(actor, Actor):
        return actor
    return Actor(
        user_id=str(actor.get("user_id")) if actor.get("user_id") is not None else None,
        role=str(actor.get("role")) if actor.get("role") is not None else None,
    )


def map_orthus_decision_to_copilot(decision: str) -> str:
    mapping = {
        "allow": "allow",
        "log_only": "allow",
        "require_approval": "ask",
        "block": "deny",
    }
    return mapping.get(str(decision), "ask")


def _format_reason(result: FirewallResult) -> str:
    codes = ", ".join(result.reason_codes) if result.reason_codes else "-"
    return f"Orthus decision={result.decision} risk={result.risk:.2f} reason_codes={codes}"


def make_on_pre_tool_use_hook(
    *,
    firewall: FirewallEngine | None = None,
    actor: Actor | Mapping[str, object] | None = None,
    text_provider: Callable[[Any, Any], str | None] | None = None,
    session_context_provider: Callable[[Any, Any], Mapping[str, object] | None] | None = None,
):
    engine = firewall or FirewallEngine()
    normalized_actor = _normalize_actor(actor)

    async def on_pre_tool_use(input_data: Any, invocation: Any) -> dict[str, str]:
        tool_name = _get_value(input_data, "toolName", "tool_name", "name")
        tool_args = _get_value(input_data, "toolArgs", "tool_args", "args", "arguments")
        tool_description = _get_value(input_data, "toolDescription", "tool_description", "description")
        session_id = _get_value(input_data, "session_id", "sessionId")
        if session_id is None:
            session_id = _get_value(invocation, "session_id", "sessionId")

        session_context = dict(session_context_provider(input_data, invocation) or {}) if session_context_provider else {}
        if session_id is not None:
            session_context.setdefault("session_id", str(session_id))

        text = text_provider(input_data, invocation) if text_provider else _get_value(input_data, "text", "prompt", "content")

        result = engine.validate_action(
            FirewallRequest(
                text=str(text) if text is not None else None,
                tool_call=ToolCall(
                    name=str(tool_name or ""),
                    args=_as_dict(tool_args),
                    description=str(tool_description) if tool_description is not None else None,
                ),
                actor=normalized_actor,
                session_context=session_context,
            )
        )

        copilot_decision = map_orthus_decision_to_copilot(result.decision)
        if copilot_decision == "allow":
            return {"permissionDecision": "allow"}
        return {
            "permissionDecision": copilot_decision,
            "permissionDecisionReason": _format_reason(result),
        }

    return on_pre_tool_use
