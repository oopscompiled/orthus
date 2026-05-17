from __future__ import annotations

import time

import pytest

from api.engine.pipeline import FirewallEngine, FirewallRequest, ToolCall


def _sample_payload() -> str:
    base = (
        "Customer support thread summary. "
        "User asks for account update and billing clarification. "
        "Include recent notes, constraints, and policy-safe response guidance. "
    )
    payload = (base * 14)[:1800]
    return payload


@pytest.mark.benchmark
def test_pipeline_latency_benchmark(benchmark: pytest.BenchmarkFixture) -> None:
    engine = FirewallEngine()
    request = FirewallRequest(
        text=_sample_payload(),
        tool_call=ToolCall(name="search_tickets", args={"query": "billing issue"}),
        session_context={},
    )
    result = benchmark(engine.validate_action, request)
    assert result.decision in {"allow", "log_only", "require_approval", "block"}


def test_pipeline_latency_manual_soft_bound() -> None:
    engine = FirewallEngine()
    request = FirewallRequest(
        text=_sample_payload(),
        tool_call=ToolCall(name="search_tickets", args={"query": "billing issue"}),
        session_context={},
    )

    start = time.perf_counter()
    for _ in range(500):
        engine.validate_action(request)
    elapsed = time.perf_counter() - start

    # Generous environment-agnostic bound.
    assert elapsed < 5.0
