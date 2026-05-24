from __future__ import annotations

from fastapi import FastAPI

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, ToolCall

from .schemas import FirewallRequestInput, FirewallResponseOutput

app = FastAPI(title="Orthus API", version="0.1.0")
firewall_engine = FirewallEngine()


def _to_engine_request(payload: FirewallRequestInput) -> FirewallRequest:
    tool_call = None
    if payload.tool_call is not None:
        tool_call = ToolCall(
            name=payload.tool_call.name,
            args=dict(payload.tool_call.args),
            description=payload.tool_call.description,
            result=payload.tool_call.result,
        )

    actor = None
    if payload.actor is not None:
        actor = Actor(user_id=payload.actor.user_id, role=payload.actor.role)

    return FirewallRequest(
        text=payload.text,
        tool_call=tool_call,
        actor=actor,
        session_context=dict(payload.session_context),
    )


def _to_response(result, *, debug: bool) -> FirewallResponseOutput:
    return FirewallResponseOutput(
        decision=result.decision,
        risk=result.risk,
        reason_codes=list(result.reason_codes),
        route=result.route,
        routes=list(result.routes),
        matched_rules=list(result.matched_rules) if debug else [],
        flags=list(result.flags),
        updated_session_context=dict(result.updated_session_context),
        latency_ms=float(result.latency_ms),
        normalized=result.normalized if debug else None,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan-tool-call", response_model=FirewallResponseOutput)
def scan_tool_call(payload: FirewallRequestInput) -> FirewallResponseOutput:
    req = _to_engine_request(payload)
    result = firewall_engine.scan_tool_call(req)
    return _to_response(result, debug=payload.debug)


@app.post("/validate-action", response_model=FirewallResponseOutput)
def validate_action(payload: FirewallRequestInput) -> FirewallResponseOutput:
    req = _to_engine_request(payload)
    result = firewall_engine.validate_action(req)
    return _to_response(result, debug=payload.debug)
