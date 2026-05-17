"""Dependency-free Anthropic/Claude Agent SDK guard adapter skeleton.

This module does not import anthropic SDK and does not make network calls.
It demonstrates where Orthus should run before real tool execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, FirewallResult, ToolCall


@dataclass(slots=True)
class GuardedToolCall:
    tool_name: str
    tool_args: dict[str, object]
    text: str | None = None
    actor: Actor | dict[str, object] | None = None
    session_context: dict[str, object] | None = None
    tool_description: str | None = None
    tool_result: str | None = None


@dataclass(slots=True)
class GuardDecision:
    decision: str
    risk: float
    reason_codes: list[str]
    matched_rules: list[str]


class OrthusGuardError(PermissionError):
    def __init__(self, *, decision: str, risk: float, reason_codes: list[str], matched_rules: list[str]) -> None:
        self.decision = decision
        self.risk = risk
        self.reason_codes = list(reason_codes)
        self.matched_rules = list(matched_rules)
        super().__init__(
            f"Orthus denied execution: decision={decision}, risk={risk:.2f}, reason_codes={','.join(reason_codes)}"
        )


class OrthusBlockedError(OrthusGuardError):
    pass


class OrthusApprovalRequired(OrthusGuardError):
    pass


def _normalize_actor(actor: Actor | dict[str, object] | None) -> Actor | None:
    if actor is None:
        return None
    if isinstance(actor, Actor):
        return actor
    if isinstance(actor, dict):
        return Actor(
            user_id=str(actor.get("user_id")) if actor.get("user_id") is not None else None,
            role=str(actor.get("role")) if actor.get("role") is not None else None,
        )
    return None


def build_firewall_request(
    *,
    tool_name: str,
    tool_args: dict[str, object],
    actor: Actor | dict[str, object] | None = None,
    text: str | None = None,
    session_context: dict[str, object] | None = None,
    tool_description: str | None = None,
    tool_result: str | None = None,
) -> FirewallRequest:
    return FirewallRequest(
        text=text,
        tool_call=ToolCall(
            name=tool_name,
            args=dict(tool_args),
            description=tool_description,
            result=tool_result,
        ),
        actor=_normalize_actor(actor),
        session_context=dict(session_context or {}),
    )


def guard_tool_call(
    *,
    firewall: FirewallEngine,
    tool_name: str,
    tool_args: dict[str, object],
    actor: Actor | dict[str, object] | None = None,
    text: str | None = None,
    session_context: dict[str, object] | None = None,
    tool_description: str | None = None,
    tool_result: str | None = None,
) -> FirewallResult:
    request = build_firewall_request(
        tool_name=tool_name,
        tool_args=tool_args,
        actor=actor,
        text=text,
        session_context=session_context,
        tool_description=tool_description,
        tool_result=tool_result,
    )
    return firewall.validate_action(request)


def should_execute(result: FirewallResult) -> bool:
    return result.decision in {"allow", "log_only"}


def assert_allowed(result: FirewallResult) -> None:
    if result.decision == "block":
        raise OrthusBlockedError(
            decision=result.decision,
            risk=result.risk,
            reason_codes=result.reason_codes,
            matched_rules=result.matched_rules,
        )
    if result.decision == "require_approval":
        raise OrthusApprovalRequired(
            decision=result.decision,
            risk=result.risk,
            reason_codes=result.reason_codes,
            matched_rules=result.matched_rules,
        )


def guard_tool(
    *,
    firewall: FirewallEngine,
    tool_name: str,
    func: Callable[..., object],
    actor: Actor | dict[str, object] | None = None,
    session_context: dict[str, object] | None = None,
    text_provider: Callable[..., str] | None = None,
) -> Callable[..., object]:
    def _wrapped(*args: Any, **kwargs: Any) -> object:
        tool_args = dict(kwargs)
        text = text_provider(*args, **kwargs) if text_provider is not None else None
        result = guard_tool_call(
            firewall=firewall,
            tool_name=tool_name,
            tool_args=tool_args,
            actor=actor,
            text=text,
            session_context=session_context,
        )
        assert_allowed(result)
        return func(*args, **kwargs)

    return _wrapped
