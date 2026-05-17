# Support Copilot Demo

This demo shows Orthus validating AI-proposed support/admin actions before execution.

Doctrine:

**Untrusted context can request actions, but it cannot grant authority.**

## Why this matters

Support/admin copilots read untrusted tickets, emails, and notes. Poisoned content can try to steer the agent into risky actions (bulk export, attacker-directed refunds, etc.).

Orthus sits between agent proposals and execution, and returns a deterministic decision.

## Run

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

## Scenarios

1. Benign support lookup
2. Poisoned support ticket tries bulk export
3. Poisoned support ticket tries refund to attacker
4. Safe response draft

The demo carries `session_context` across steps, so you can observe stateful risk behavior.

## What is simulated

- The proposed tool/action call an agent might produce
- Orthus decision/risk/reason codes/matched rules
- Session context updates

## What is not included

- No external LLM/API calls
- No Claude SDK/OpenAI SDK integration
- No network calls

In production, Orthus is the pre-execution firewall between tool-using agents and real backend actions.
