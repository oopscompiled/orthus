# MCP Server Guard Demo

This demo simulates MCP-style operations and validates them with Orthus before execution.

It is a simulation, not a full MCP server implementation.

Orthus should sit before MCP tool/resource execution.

**Untrusted tool descriptions, resource contents, or user prompts can request actions, but cannot grant authority.**

## Run

```bash
uv run python examples/mcp_server_guard/demo.py
```

Debug mode:

```bash
uv run python examples/mcp_server_guard/demo.py --debug
```

JSON mode:

```bash
uv run python examples/mcp_server_guard/demo.py --json
```

## Scenarios

1. Normal resource read (`resources/read` on workspace path)
2. Sensitive resource read (`resources/read` on `/etc/shadow`)
3. Subscription fanout/race (`subscribe_race` with high `parallel_ops`)
4. Partial subscription flood (stateful sequence)
5. Unsubscribe then notify after free (stateful sequence)

These demonstrate pre-execution action validation for MCP-style flows.
