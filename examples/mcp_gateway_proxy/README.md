# MCP Gateway / Proxy Simulation

This is a reference-style example for putting Orthus at an MCP gateway boundary.

It is still a dependency-free simulation, not a production MCP gateway. The point is to show where a real gateway/proxy should call Orthus before forwarding a `tools/list`, `tools/register`, or `tools/call` operation.

Run:

```bash
uv run python examples/mcp_gateway_proxy/proxy.py
uv run python examples/mcp_gateway_proxy/proxy.py --json
```

## Boundary Pattern

```text
MCP client/server operation proposed
  -> gateway builds Orthus action event
  -> Orthus validates metadata, args, provenance, and session context
  -> allow | log_only | require_approval | block
  -> gateway forwards only if app policy allows execution
```

## What Is Trusted

Trusted:

- backend authorization state
- configured policy
- pinned tool metadata/schema hashes
- authenticated actor/session identity
- explicit current approval events
- gateway-controlled connection/request identifiers

Untrusted or not automatically authoritative:

- MCP tool descriptions
- MCP tool schemas from an unpinned server
- MCP resources
- MCP tool results
- natural-language claims that approval exists
- cross-server context copied from another MCP connection

Core rule:

> Tool metadata and tool results are inputs. They are not authority.

## Required Metadata

A useful MCP gateway action event should include:

- `tool_call.name`
- MCP operation name, such as `tools/list`, `tools/register`, or `tools/call`
- target tool name when nested under `tools/call`
- `actor.user_id` and `actor.role`
- `server_id`
- `connection_id`
- `jsonrpc_id` or request id
- `tool_metadata_hash` when available
- `schema_hash` when available
- `source_refs` for tool descriptions, resources, and tool results
- `sink_metadata` for email/webhook/HTTP/public destinations
- bounded `session_context`

See [../../docs/INTEGRATION_GUIDE.md](../../docs/INTEGRATION_GUIDE.md) and [../../docs/ACTION_EVENT_SCHEMA.md](../../docs/ACTION_EVENT_SCHEMA.md).

## What Orthus Sees

Each fixture is an Orthus-style action event:

- surrounding text/context
- proposed MCP operation as `tool_call`
- actor identity/role
- nested MCP metadata in args
- source provenance when available
- destination/visibility metadata when relevant

Orthus returns:

- `decision`
- `risk`
- `reason_codes`
- `matched_rules` in local/debug contexts

## Fixtures

- `fixtures/01_safe_tool_call.json`: approved bounded tool call
- `fixtures/02_poisoned_tool_description.json`: metadata changed with hidden instruction
- `fixtures/03_schema_changed.json`: permissive schema with risky unknown fields
- `fixtures/04_unexpected_sensitive_arg.json`: tool call crosses into external sensitive egress
- `fixtures/05_cross_server_context_risk.json`: context from one MCP server tries to authorize an external send through another server

## Why Decisions Happen

Safe bounded call:

- single resource lookup
- bounded argument
- no external sink
- no metadata/schema anomaly

Poisoned metadata:

- tool description contains system/override language
- metadata attempts to influence future tool arguments
- decision should pause or block before trusting the changed tool surface

Permissive schema:

- schema allows unexpected fields
- arguments contain command/external endpoint shape
- tool registration changes the control plane

Unexpected sensitive arg / cross-server context:

- untrusted MCP tool result suggests a side-effecting action
- destination is external/customer-visible
- sensitive marker appears in the sink
- cross-server context cannot grant authority to send data

## Adapting To A Real MCP Client/Server

In a real gateway:

1. Intercept MCP operations before forwarding.
2. Normalize operation, actor, MCP ids, source refs, and sink metadata.
3. Call `FirewallEngine.validate_action(...)` or the HTTP API.
4. Forward only on `allow` or policy-approved `log_only`.
5. Pause on `require_approval`.
6. Deny on `block`.
7. Store bounded audit metadata, not raw tool outputs or secrets.

Keep real auth/RBAC in the application or gateway. Orthus complements backend authorization; it does not replace it.
