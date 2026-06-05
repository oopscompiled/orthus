# GitHub Copilot SDK Guard

Orthus can guard GitHub Copilot SDK tool calls before execution by plugging into a pre-tool-use hook.

The integration is dependency-free:
- it does not import the GitHub Copilot SDK
- it does not make network calls
- it wraps the existing `FirewallEngine.validate_action(...)` API

## Why Pre-Tool-Use

Pre-tool-use is the right control point because Orthus is an action firewall.

Prompt scanners ask whether text is suspicious.
Orthus asks whether the proposed tool call should execute.

The hook runs after a tool call has been proposed and before the tool runs, so it can map Orthus decisions to Copilot permission decisions.

## Decision Mapping

| Orthus decision | Copilot hook decision |
|---|---|
| `allow` | `allow` |
| `log_only` | `allow` |
| `require_approval` | `ask` |
| `block` | `deny` |
| unknown | `ask` |

## Minimal Python Snippet

```python
from api.engine.pipeline import FirewallEngine
from api.integrations.github_copilot import make_on_pre_tool_use_hook

firewall = FirewallEngine()

on_pre_tool_use = make_on_pre_tool_use_hook(
    firewall=firewall,
    actor={"user_id": "support_1", "role": "support_agent"},
)

# In a Copilot SDK app just pass the hook into the session configuration:
# hooks={"on_pre_tool_use": on_pre_tool_use}
```

The hook returns:

```json
{"permissionDecision": "allow"}
```

or:

```json
{
  "permissionDecision": "deny",
  "permissionDecisionReason": "Orthus decision=block risk=0.95 reason_codes=..."
}
```

## Dry Run

Run the local example without GitHub auth or SDK installation:

```bash
uv run python examples/github_copilot_sdk_guard/demo.py
```

The demo calls the hook directly with synthetic input:
- benign `search_kb` -> `allow`
- risky `export_customer_data(scope=all)` -> `deny` or `ask`

## Security Notes

- Orthus complements GitHub/Copilot permissions; it does not replace backend auth/RBAC.
- Do not pass real secrets to demos.
- Keep `debug=false` for sensitive logs.
- Prefer `ask`/`deny` for external sends, filesystem writes, DB writes, plugin/tool registration, and MCP lifecycle operations.
- Keep application-side authorization checks on the backend tool itself.

## Reference

GitHub documents pre-tool-use hooks as returning `permissionDecision` values including `allow`, `deny`, and `ask`:
- https://docs.github.com/en/copilot/how-tos/copilot-sdk/use-hooks/pre-tool-use
