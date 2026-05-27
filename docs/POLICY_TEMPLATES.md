# Policy Templates

Orthus policy is an application-side authorization/risk layer.

It should complement, not replace, backend authorization/RBAC.

Policy should be written around:
- actions
- actor roles
- destinations
- data sensitivity
- approval requirements

Use decision-first handling; `reason_codes` explain why a decision was returned.

## Principles

- Default allow for low-impact read/search/draft actions.
- Require approval for sensitive writes, exports, refunds, external sends, plugin installs, and scheduled tasks.
- Block obvious high-risk combinations.
- Keep policy small and explicit.
- Do not encode every attack string in policy; use rules/validators for threat patterns.
- Do not trust untrusted content to grant authority.

## Common Action Categories

### Low-Impact Actions

Examples:
- `search_kb`
- `search_tickets`
- `read_documentation`
- `generate_response_draft`

Suggested:
- `allow` or `log_only`

### Sensitive Reads

Examples:
- `read_file`
- `query_database`
- `export_customer_data`
- `get_download_link`

Suggested:
- `require_approval` for sensitive paths/data scopes
- `block` obvious secret/system paths

### External Sends / Egress

Examples:
- `send_email`
- `send_message`
- `post_teams_message`
- `http_request`
- `set_webhook`

Suggested:
- `require_approval` or `block` when destination is external/untrusted
- elevate when payload may contain sensitive data

### Financial / Account Actions

Examples:
- `refund_payment`
- `change_plan`
- `update_billing`
- `issue_credit`

Suggested:
- `require_approval` by default
- `block` suspicious destination/amount/actor mismatch patterns

### MCP / Plugin / Tool Lifecycle

Examples:
- `tools/register`
- `plugins/install`
- `resources/subscribe`
- `initialize`
- `sampling/createMessage`

Suggested:
- `require_approval` for high-risk capabilities and external plugin sources
- elevate/block protocol anomalies
- elevate when sampling is used to generate dangerous tool calls

### Scheduled / Unattended Actions

Examples:
- `create_scheduled_task`
- `automation/create`
- `cron/create`

Suggested:
- `require_approval` when task can send/export/read sensitive data or contact external destinations

## Example Template: Support Copilot

```yaml
tools:
  search_tickets:
    risk: low
    log: true

  search_kb:
    risk: low
    log: true

  generate_response_draft:
    risk: low
    log: true

  refund_payment:
    risk: high
    require_approval: always

  export_customer_data:
    risk: critical
    require_approval: always
    block_if:
      - actor.role == "support_agent" and args.scope == "all"

  send_email:
    risk: high
    require_approval_if:
      - destination_domain_is_external == true

block_external_domains:
  enabled: true
  allowlist:
    - "internal.company.com"
    - "localhost"
```

Intent:
- allow read/search/draft workflows
- require approval for refunds
- block full customer export by low-trust support role
- require approval for external email destinations

## Example Template: Developer Agent

```yaml
tools:
  read_documentation:
    risk: low
    log: true

  search_code:
    risk: low
    log: true

  execute_command:
    risk: critical
    require_approval: always

  write_file:
    risk: high
    require_approval: always

  read_file:
    risk: medium
    require_approval_if:
      - args.path contains "/etc/"
      - args.path contains ".env"

  plugins/install:
    risk: high
    require_approval: always

  tools/register:
    risk: high
    require_approval: always

  http_request:
    risk: medium
    require_approval_if:
      - destination_domain_is_external == true

  set_webhook:
    risk: high
    require_approval_if:
      - destination_domain_is_external == true
```

Intent:
- allow documentation/search
- require approval for command/file mutation actions
- elevate sensitive file reads
- require approval for plugin/tool registration and external egress

## Example Template: MCP Server Guard

```yaml
tools:
  resources/read:
    risk: medium
    log: true

  resources/subscribe:
    risk: high
    require_approval: always

  tools/register:
    risk: high
    require_approval: always

  plugins/install:
    risk: high
    require_approval: always

  initialize:
    risk: medium
    require_approval_if:
      - protocol_version_is_unknown == true

  sampling/createMessage:
    risk: medium
    require_approval_if:
      - args.include_tool_calls == true
```

Intent:
- allow normal read operations
- require approval for subscription/tool/plugin lifecycle operations
- elevate protocol anomalies and risky sampling behavior
- pair with validators that detect sensitive URI/resource patterns

## Integration Checklist

- Identify high-impact actions.
- Identify actor roles.
- Identify internal vs external destinations.
- Identify sensitive data scopes.
- Decide `allow` / `log_only` / `require_approval` / `block` per action class.
- Add safe false-positive cases.
- Test with `make eval` and local API smoke.

## Caveats

- Policy is not a substitute for backend authorization.
- Policy should not depend only on natural-language text.
- Keep `debug=false` in production unless intentionally debugging.
- Review `reason_codes` to tune policy over time.
