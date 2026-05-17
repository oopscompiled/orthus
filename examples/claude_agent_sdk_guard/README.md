# Claude Agent SDK Guard Adapter (Skeleton)

This example shows where Orthus sits between an agent runtime and real tool execution.

It is **not** the real Claude SDK runtime and does not call Anthropic APIs.

Doctrine:

**Untrusted context can request actions, but it cannot grant authority.**

## What this demonstrates

- Guarding a proposed tool call via `guard_tool_call(...)`
- Wrapping a local tool function via `guard_tool(...)`
- Blocking/approval before execution for risky actions

In a real Claude Agent SDK app, call Orthus before executing tools.

## Run

```bash
uv run python examples/claude_agent_sdk_guard/demo.py
```

## Notes

- No `anthropic` dependency required.
- No API keys required.
- No network calls are made.
