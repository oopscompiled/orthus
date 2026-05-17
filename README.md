# Orthus

AI Action Firewall for tool-using agents.

Validate tool calls, MCP operations, and backend actions before execution.

Let agents use tools. Don’t let them blindly execute.

## Why Orthus Exists

Agents do not only answer prompts anymore. They call tools, read files, export data, issue refunds, send emails, mutate configs, and interact with MCP resources.

Prompt scanning is not enough. The critical control point is before execution.

Prompt guardrail asks:
- "Is this text unsafe?"

Orthus asks:
- "Should this proposed action execute right now?"

## Trust Domain Doctrine

**Untrusted context can request actions, but it cannot grant authority.**

Trusted context:
- developer policy
- signed tool schema
- actor role
- backend authorization
- session state

Untrusted context:
- user prompt
- support ticket
- retrieved document
- web page
- MCP tool description
- tool result

A poisoned ticket may ask for customer export, but it cannot give a support agent permission to export all customer data.

## Quickstart (30-Second Demo)

```bash
uv run python examples/support_copilot/demo.py
```

Debug mode:

```bash
uv run python examples/support_copilot/demo.py --debug
```

JSON mode:

```bash
uv run python examples/support_copilot/demo.py --json
```

## What the Demo Shows

1. Benign support request:
- proposed read-only action
- Orthus returns `allow` or `log_only`

2. Poisoned support ticket:
- hidden/untrusted instruction tries bulk export/refund behavior
- Orthus returns `require_approval` or `block`

3. Sensitive backend action:
- `export_customer_data(scope="all")`
- Orthus returns non-allow with reason codes

4. Session risk memory:
- `session_context` is carried across steps
- Orthus updates risk/trend state deterministically

## Core API

```python
from api.engine.pipeline import FirewallEngine, FirewallRequest, ToolCall, Actor

engine = FirewallEngine()

result = engine.validate_action(
    FirewallRequest(
        text="Customer asks for a full export.",
        tool_call=ToolCall(name="export_customer_data", args={"scope": "all"}),
        actor=Actor(user_id="support_123", role="support_agent"),
        session_context={},
    )
)

print(result.decision, result.risk, result.reason_codes)
```

## Pipeline Overview

Deterministic layers:
- normalizer (encoding/obfuscation cleanup)
- rules/signatures + structured validators
- policy evaluation
- decision aggregation
- session risk scoring

See [docs/architecture.md](docs/architecture.md) for the pipeline diagram.

## Public vs Private Rule Packs

Public repo includes high-precision deterministic basic packs.
Private intelligence packs can be loaded externally.

See [docs/rule-pack-boundary.md](docs/rule-pack-boundary.md).

## Local Validation

```bash
uv run pytest tests/ -v
```

## Notes

- The support-copilot demo does not call Claude, OpenAI, or any external LLM API.
- Orthus is model-agnostic: it validates actions proposed by any tool-using agent stack.
