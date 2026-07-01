# MCP Gateway / Proxy Simulation

This example shows how Orthus can sit at an MCP-style gateway boundary.

It is dependency-free and does not implement a real MCP server. It simulates the pre-forwarding decision point a gateway/proxy would use before forwarding a `tools/list`, `tools/register`, or `tools/call` operation.

Run:

```bash
uv run python examples/mcp_gateway_proxy/proxy.py
uv run python examples/mcp_gateway_proxy/proxy.py --json
```

Fixtures:

- `fixtures/01_safe_tool_call.json`: approved bounded tool call
- `fixtures/02_poisoned_tool_description.json`: metadata changed with hidden instruction
- `fixtures/03_schema_changed.json`: permissive schema with risky unknown fields
- `fixtures/04_unexpected_sensitive_arg.json`: tool call crosses into external sensitive egress

Demo flow:

1. MCP tool call is safe and bounded.
2. Tool metadata changes.
3. Schema becomes permissive and introduces risky fields.
4. Tool call attempts to send sensitive content externally.
5. Orthus returns `require_approval` or `block` with reason codes explaining the boundary.

Security notes:

- Tool metadata is not authority.
- MCP tool results are not authority.
- Schema changes and tool description changes should be reviewable.
- Untrusted context may inform an answer, but it cannot authorize external sends, writes, exports, or privileged operations.
