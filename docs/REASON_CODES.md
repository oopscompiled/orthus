# Reason Codes

`reason_codes` explain why Orthus returned `allow`, `log_only`, `require_approval`, or `block`.

They are intended for:
- logging and audit trails
- UI/user-facing explanations
- alert routing
- policy tuning and false-positive review

Important:
- `reason_codes` are not a stable legal/compliance taxonomy.
- Integrations should branch primarily on `decision`, not on exact reason code strings.
- Reason code sets can evolve across minor versions.

## Recommended Handling

Decision-first behavior:

- `allow`: execute normally.
- `log_only`: execute, log event, optionally show low-risk warning.
- `require_approval`: pause execution and request human approval or a higher-trust workflow.
- `block`: do not execute.

Use `reason_codes` to:
- explain decisions to humans
- tune policy/rules
- route notifications
- monitor false positives
- enrich event logs

## Families

Examples below are common in Orthus v0.1.x and may expand over time.

### Policy

Examples:
- `policy_block_condition_matched`
- `policy_require_approval_condition`
- `policy_require_approval_always`
- `policy_risk_high`
- `policy_risk_critical`
- `policy_blocked_domain`

Meaning:
- Policy engine matched a configured condition.

Integrator action:
- Respect decision; do not auto-bypass policy-driven block/approval outcomes.

### Prompt / Instruction Injection

Examples:
- `instruction_override_attempt`
- `hidden_instruction_marker`
- `mcp_hidden_instruction`
- `recent_prompt_injection`

Meaning:
- Untrusted context appears to be trying to alter instructions or tool behavior.

### Data Exfiltration

Examples:
- `bulk_customer_data_access`
- `external_destination`
- `outbound_content_exfil`
- `scheduled_external_egress`
- `spreadsheet_formula_exfil`
- `public_comment_secret_exfil`
- `auth_redirect_exfil_risk`

Meaning:
- Action may move sensitive data to an external or hidden sink.

### Sensitive Path / Resource Access

Examples:
- `sensitive_path_access`
- `sensitive_path_reference`
- `path_traversal_marker`
- `schema_path_traversal`
- `environment_secret_dump`

Meaning:
- Action references sensitive paths/resources or traversal patterns.

### Tool / Plugin / Schema Abuse

Examples:
- `tool_discovery`
- `tool_shadowing`
- `external_plugin_source`
- `suspicious_schema_parameter`
- `command_injection`
- `readonly_database_write_attempt`
- `database_ransomware_pattern`

Meaning:
- Tooling metadata, registration, schema, or arguments appear unsafe.

### MCP / Protocol / Lifecycle

Examples:
- `partial_subscription_flood`
- `notify_after_unsubscribe`
- `protocol_version_regression`
- `security_capability_stripping`
- `subscription_chain_amplification`
- `event_sender_spoofing`
- `state_key_pollution`
- `payment_verification_bruteforce`
- `payment_card_enumeration`

Meaning:
- Suspicious MCP/session/protocol lifecycle behavior.

### Session Risk

Examples:
- `rising_session_risk`
- `repeated_blocked_attempts`
- `sensitive_tool_sequence`
- `high_velocity`

Meaning:
- Session memory/sequence context increased risk.

## ℹ️ Known Caveats

- `reason_codes` are explanatory, not exhaustive.
- Multiple reason codes can appear for one decision.
- `debug=false` may hide `matched_rules` but still return `reason_codes`.
- Absence of reason codes on `allow` does not mean zero risk.
- Risk score is advisory; decision is authoritative.

## ⚠️ Debug Behavior

- `debug=false`: hides `normalized` and `matched_rules` in API output.
- `debug=true`: may expose `normalized` text and `matched_rules` for local/dev diagnostics.
- Avoid enabling `debug=true` in production logs with sensitive content unless explicitly intended.

## Examples

Allow:

```json
{
  "decision": "allow",
  "risk": 0.01,
  "reason_codes": []
}
```

Require approval (policy + sensitive path):

```json
{
  "decision": "require_approval",
  "risk": 0.79,
  "reason_codes": [
    "policy_require_approval_condition",
    "sensitive_path_access"
  ]
}
```

Block (exfil + injection):

```json
{
  "decision": "block",
  "risk": 0.95,
  "reason_codes": [
    "instruction_override_attempt",
    "external_destination",
    "bulk_customer_data_access"
  ]
}
```