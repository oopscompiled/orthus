# LangChain-Style Tool Guard Example

This example shows a generic hook pattern for agent frameworks that execute tools.

It does not import LangChain. The integration point is intentionally generic:

```text
before_tool_execution(tool_name, args, context)
  -> build Orthus event
  -> validate
  -> allow | log_only | require_approval | block
```

Run:

```bash
uv run python examples/langchain_style_tool_guard/demo.py
uv run python examples/langchain_style_tool_guard/demo.py --json
```

Use this pattern in any framework that lets you intercept tool execution before the actual tool function is called.
