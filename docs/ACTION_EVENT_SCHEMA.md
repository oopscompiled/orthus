# Action Event Schema

Orthus validates proposed actions before execution. The more structured metadata an integration provides, the less Orthus has to infer from text.

This document defines recommended metadata conventions for integrations. It is guidance, not a new runtime API contract.

## Core Principle

Untrusted context may inform an answer, but it must not authorize side-effecting actions.

Authority should come from structured application state:
- actor identity and role
- backend authorization
- policy
- explicit user intent
- trusted approval event
- tool metadata
- bounded session context

## Minimal Integration

A minimal integration should provide enough data for action-level policy decisions.

Required fields:

```yaml
actor:
  role: support_agent

tool:
  name: send_email
  category: external_egress

source_trust: untrusted

args:
  to: customer@example.com
  body: message body
```

Recommended minimum:
- `actor.user_id`
- `actor.role`
- `tool.name`
- `tool.category`
- `source_trust`
- `args`
- `session_id` when available

Minimal integrations are enough for many deterministic checks, but they are weaker for provenance and approval binding.

## Strong Integration

A strong integration should bind proposed actions to trusted intent, current event state, and destination metadata.

Recommended fields:

```yaml
actor:
  user_id: support_1
  role: support_agent

tool:
  name: export_customer_data
  category: data_export
  server_id: crm_mcp

args:
  scope: current_ticket_customer
  format: csv

source_refs:
  - id: ticket_123
    type: support_ticket
    trust: untrusted
  - id: user_click_456
    type: user_intent
    trust: trusted

trusted_user_intent:
  event_id: user_click_456
  action: export_customer_data
  scope: current_ticket_customer
  expires_at: 2026-07-01T12:30:00Z

sink_metadata:
  destination_type: download
  visibility: internal
  domain: company.internal

permission_scope:
  data_scope: current_ticket_customer
  environment: staging
  role_allowed: true

session:
  current_event_id: evt_789
  approval_event_id: approval_456
  connection_id: conn_abc
  jsonrpc_id: "42"
```

Strong metadata helps Orthus distinguish:
- user-authorized actions from tool-result suggestions
- current approvals from stale approvals
- internal destinations from external sinks
- safe docs/search workflows from action execution
- MCP request/result binding from cross-event replay

## Field Reference

### `actor`

Identity performing or proposing the action.

Useful fields:
- `user_id`
- `role`
- `tenant_id`
- `auth_level`
- `environment`

### `tool`

The action surface.

Useful fields:
- `name`
- `category`
- `server_id` for MCP
- `namespace`
- `version`
- `metadata_hash`
- `capabilities`

Suggested categories:
- `read_only_search`
- `sensitive_read`
- `file_write`
- `shell`
- `database_read`
- `database_write`
- `external_egress`
- `payment`
- `account_admin`
- `mcp_lifecycle`
- `plugin_lifecycle`
- `browser`
- `scheduled_task`

### `source_refs`

Where the model got the information that influenced the action.

Useful fields:
- `id`
- `type`
- `trust`
- `origin`
- `retrieved_at`
- `content_hash`

Examples of `type`:
- `user_message`
- `support_ticket`
- `web_page`
- `document`
- `tool_result`
- `mcp_resource`
- `mcp_tool_description`
- `memory`
- `admin_approval`

Examples of `trust`:
- `trusted`
- `semi_trusted`
- `untrusted`
- `unknown`

### `trusted_user_intent`

A structured binding between the current user/admin instruction and the proposed action.

Useful fields:
- `event_id`
- `action`
- `scope`
- `resource_id`
- `approved_destination`
- `expires_at`

Do not treat natural-language text inside untrusted content as trusted user intent.

### `sink_metadata`

Destination and visibility of output or side effects.

Useful fields:
- `destination_type`
- `domain`
- `url_host`
- `visibility`
- `recipient_type`
- `public`
- `external`
- `contains_sensitive_material`

### `permission_scope`

Application-side authorization context.

Useful fields:
- `data_scope`
- `environment`
- `role_allowed`
- `requires_approval`
- `approval_policy_id`

### MCP Metadata

Recommended MCP fields:
- `server_id`
- `connection_id`
- `jsonrpc_id`
- `request_id`
- `result_id`
- `tool_name`
- `tool_metadata_hash`
- `schema_hash`
- `protocol_version`
- `subscription_id`

These fields support request/result binding, tool metadata change detection, schema pinning, and replay resistance.

## Minimal vs Strong Integration

| Capability | Minimal | Strong |
|---|---:|---:|
| Basic tool/arg validation | yes | yes |
| Role-aware policy | partial | yes |
| Source trust decisions | partial | yes |
| Trusted intent binding | no | yes |
| Approval freshness checks | no | yes |
| MCP request/result binding | no | yes |
| Lower false positives | limited | better |
| Strong audit/replay | limited | better |

## Privacy Guidance

Integrations should avoid sending raw secrets or large raw tool outputs to Orthus when a bounded marker is enough.

Prefer:
- hashes
- resource identifiers
- trust labels
- destination metadata
- compact markers such as `recent_sensitive_read=true`

Avoid storing or forwarding:
- raw auth headers
- raw API keys
- raw tool outputs
- full customer records
- private logs
- large prompt transcripts

## Implementation Checklist

1. Identify high-impact actions.
2. Assign tool categories.
3. Attach actor role and user id.
4. Label source trust.
5. Add destination metadata for sends/exports/webhooks/HTTP/browser actions.
6. Bind side effects to trusted user intent when available.
7. Add current event and approval event IDs.
8. Include MCP connection/request metadata for MCP integrations.
9. Run local evals and safe-FP tests before tightening policy.
