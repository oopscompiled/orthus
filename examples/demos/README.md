# Orthus Demo Package

These demos are small market-proof scenarios. Each folder shows:

```text
input/context -> proposed action -> Orthus decision -> reason codes
```

Demos:

- `role_confusion_webpage_env_exfil`: the model gets confused, but the action boundary blocks external secret egress.
- `mcp_tool_poisoning`: tool metadata is not authority.
- `coding_agent_shell_access`: text cannot manufacture approval for shell execution.
- `safe_scary_text_allowed`: Orthus is not a keyword blocker.

Each demo contains:

- `README.md`
- `attack_or_input.md`
- `event.json`
- `policy.yaml`
- `expected_decision.json`
- `demo.py`

Run one demo:

```bash
uv run python examples/demos/role_confusion_webpage_env_exfil/demo.py
```

Run all demos:

```bash
for demo in examples/demos/*/demo.py; do uv run python "$demo"; done
```
