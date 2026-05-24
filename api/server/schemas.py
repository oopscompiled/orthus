from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolCallInput(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None
    result: str | None = None


class ActorInput(BaseModel):
    user_id: str | None = None
    role: str | None = None


class FirewallRequestInput(BaseModel):
    text: str | None = None
    tool_call: ToolCallInput | None = None
    actor: ActorInput | None = None
    session_context: dict[str, Any] = Field(default_factory=dict)
    debug: bool = False


class FirewallResponseOutput(BaseModel):
    decision: str
    risk: float
    reason_codes: list[str]
    route: str
    routes: list[str]
    matched_rules: list[str] = Field(default_factory=list)
    flags: list[str]
    updated_session_context: dict[str, Any]
    latency_ms: float
    normalized: str | None = None
