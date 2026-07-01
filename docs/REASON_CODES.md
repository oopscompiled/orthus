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
- A reason code should explain an action boundary risk, not merely label scary text.

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

Do not use `reason_codes` as the only authorization mechanism. Backend auth/RBAC and application policy remain authoritative.

## Boundary-First Interpretation

When reviewing a `require_approval` or `block`, ask which boundary was crossed.

| Boundary | Typical question | Example reason codes |
|---|---|---|
| Authority | Did untrusted context try to grant permission? | `missing_trusted_user_intent`, `untrusted_context_to_action`, `policy_block_condition_matched` |
| Provenance | Is the action grounded in the current trusted event? | `action_context_provenance_gap`, `stale_or_cross_event_action_context`, `mcp_result_source_mismatch` |
| Egress | Can data leave to an external, public, or hidden sink? | `external_destination`, `outbound_content_exfil`, `callback_url_exfiltration_risk` |
| Sensitive resource | Does the action read secrets, credentials, paths, metadata, or customer data? | `sensitive_path_access`, `environment_secret_dump`, `bulk_customer_data_access` |
| Mutation/execution | Does the action write, execute, mutate, install, or schedule work? | `command_injection_argument_risk`, `arbitrary_file_write_risk`, `scheduled_external_egress` |
| Protocol/session | Is a lifecycle, request/result, or sequence invariant broken? | `protocol_version_regression`, `notify_after_unsubscribe`, `mcp_unbound_tool_result` |
| Public exposure | Could sensitive material appear in a customer/public surface? | `public_comment_secret_exfil`, `public_sensitive_update_risk`, `markdown_image_exfiltration_risk` |
| Iteration/oracle | Is the actor probing a verifier or oracle through repeated small deltas? | `tool_oracle_iteration_risk`, `payment_verification_bruteforce` |

If a reason code does not map to one of these boundaries, treat it as a candidate for future cleanup.

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
- Respect the decision. Do not auto-bypass policy-driven block/approval outcomes.
- Show the policy reason with the action category and actor role when asking for approval.
- If `policy_blocked_domain` appears, verify the destination/domain is real and parsed from an action sink, not just text.

### Prompt / Instruction Injection

Examples:
- `instruction_override_attempt`
- `instruction_injection_marker`
- `hidden_instruction_marker`
- `mcp_hidden_instruction`
- `recent_prompt_injection`
- `mcp_tool_descriptor_injection`
- `mcp_prompt_catalog_injection`
- `mcp_sampling_prompt_injection`
- `refusal_induced_leakage`
- `mcp_resource_hidden_instruction`
- `mcp_cross_server_prompt_injection`
- `stored_prompt_injection_chain`
- `llm_output_schema_escape`

Meaning:
- Untrusted context appears to be trying to alter instructions or tool behavior.

Boundary:
- Instruction text is attempting to become authority.

Integrator action:
- If no side-effecting action is proposed, `log_only` may be enough.
- If paired with export, write, execute, refund, install, send, public output, or protocol mutation, pause or block according to the decision.
- Do not suppress these globally; suppress only safe documentation/search contexts.

### Data Exfiltration / Egress

Examples:
- `bulk_customer_data_access`
- `external_destination`
- `outbound_content_exfil`
- `scheduled_external_egress`
- `spreadsheet_formula_exfil`
- `public_comment_secret_exfil`
- `auth_redirect_exfil_risk`
- `sensitive_tool_response_exposure`
- `mcp_cross_session_context_leak`
- `mcp_resource_mime_mismatch`
- `covert_http_exfiltration_risk`
- `markdown_image_exfiltration_risk`
- `multi_tool_exfiltration_chain`
- `derived_sensitive_value_exposure`
- `public_sensitive_update_risk`
- `cross_tool_scope_leakage`
- `draft_sink_exfiltration_risk`
- `latent_tool_functionality_risk`
- `stale_memory_to_sensitive_action`
- `identity_token_relay_risk`
- `privileged_header_to_untrusted_origin`
- `auth_context_boundary_bleed`
- `markdown_hyperlink_exfiltration_risk`
- `sensitive_data_in_url_component`
- `callback_url_exfiltration_risk`
- `redirect_chain_exfiltration_risk`
- `url_shortener_obfuscation_risk`
- `browser_navigation_exfiltration_risk`
- `untrusted_url_template_expansion`

Meaning:
- Action may move sensitive data to an external, public, cross-domain, rendered, redirected, or hidden sink.

Boundary:
- Data movement from trusted/private context to a less trusted destination.

Integrator action:
- For `block`, do not send the data.
- For `require_approval`, show destination, visibility, actor, and data scope to the reviewer.
- Treat internal telemetry/logging sinks as possible egress if sensitive data is included.

### Sensitive Path / Resource Access

Examples:
- `sensitive_path_access`
- `sensitive_path_reference`
- `path_traversal_marker`
- `schema_path_traversal`
- `environment_secret_dump`
- `environment_secret_harvesting`
- `cloud_metadata_credentials_access`
- `service_account_credentials_access`
- `path_traversal_argument_risk`
- `ssrf_argument_risk`
- `xxe_argument_risk`

Meaning:
- Action references sensitive paths/resources, secret stores, metadata services, traversal, SSRF, or parser risks.

Boundary:
- The proposed action crosses from ordinary app data into host/runtime/cloud/credential surfaces.

Integrator action:
- Require approval or block before reading or fetching.
- Keep documentation/search mentions safe; do not treat docs queries as file/network execution.

### Tool / Plugin / Schema Abuse

Examples:
- `tool_discovery`
- `tool_shadowing`
- `external_plugin_source`
- `suspicious_schema_parameter`
- `command_injection`
- `readonly_database_write_attempt`
- `database_ransomware_pattern`
- `mcp_tool_descriptor_tampering`
- `mcp_client_supplied_privilege`
- `sql_injection_argument_risk`
- `command_injection_argument_risk`
- `arbitrary_file_write_risk`
- `schema_coercion_argument_risk`
- `tool_surface_enumeration_attempt`
- `tool_schema_error_leakage`

Meaning:
- Tooling metadata, registration, schema, query, command, or arguments appear unsafe.

Boundary:
- A tool/control-plane surface is being expanded, shadowed, leaked, or used beyond its declared purpose.

Integrator action:
- Prefer `require_approval` for tool registration, plugin install, schema changes, or schema-error exposure.
- Prefer `block` for explicit command injection, arbitrary sensitive writes, or destructive database patterns.

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
- `mcp_shadow_endpoint_access`
- `tool_oracle_iteration_risk`
- `mcp_response_request_mismatch`
- `mcp_result_source_mismatch`
- `mcp_jsonrpc_id_reuse`
- `mcp_foreign_tool_result_injection`
- `mcp_stream_event_identity_collision`
- `mcp_stdio_frame_boundary_artifact`
- `mcp_unbound_tool_result`
- `cross_protocol_semantic_bridge`
- `capability_chain_privilege_escalation`
- `permission_scope_ambiguity`
- `implicit_permission_inheritance`
- `persistent_memory_directive_poisoning`
- `memory_authority_escalation`
- `physical_action_without_strong_approval`
- `synthetic_evidence_to_physical_action`
- `security_alert_suppression_risk`
- `cross_agent_delegation_poisoning`
- `delegated_task_provenance_gap`
- `privilege_tier_escalation_via_agent_queue`

Meaning:
- Suspicious MCP/session/protocol lifecycle behavior, request/result identity mismatch, capability escalation, persistent-memory authority, physical-action approval gap, or cross-agent delegation risk.

Boundary:
- Protocol/session state, capability scope, or identity context no longer matches the proposed action.

Integrator action:
- Do not repair protocol or lifecycle anomalies by asking the model to guess.
- Rebind to a fresh request/session/approval when possible.
- Require signed/typed envelopes for cross-agent or event-bus actions.

### Action Provenance / Intent Binding

Examples:
- `missing_trusted_user_intent`
- `untrusted_context_to_action`
- `action_context_provenance_gap`
- `stale_or_cross_event_action_context`
- `premise_injection_tool_steering`
- `goal_hijacking_plan_deviation`
- `poisoned_observation_to_action`
- `reasoning_unsupported_tool_switch`
- `intent_locked_tool_scope_violation`

Meaning:
- A side-effecting or high-impact action is not grounded in current trusted user intent, appears derived from untrusted context, lacks expected provenance references, reuses approval from another event, violates an allowed tool scope, or follows an untrusted observation/plan premise into a changed goal or less restricted tool.

Boundary:
- The action is not bound to current trusted intent.

Integrator action:
- Treat untrusted context as data only.
- Require a fresh trusted user/admin action for deploys, deletes, sends, exports, writes, refunds, validation bypass, or less-restricted tool switches.

### Session Risk

Examples:
- `rising_session_risk`
- `repeated_blocked_attempts`
- `sensitive_tool_sequence`
- `high_velocity`

Meaning:
- Session memory/sequence context increased risk.

Boundary:
- The current action is risky because of recent prior actions, not only its own arguments.

Integrator action:
- Show recent action categories in review UI when possible.
- Do not log raw secrets/tool outputs; use bounded markers and event IDs.

## v0.1.14 Audit Notes

The v0.1.14 consolidation pass keeps existing public reason code strings for compatibility and focuses on clarity.

Findings:
- Several reason codes overlap conceptually, especially around egress (`external_destination`, `outbound_content_exfil`, `callback_url_exfiltration_risk`) and path/resource access (`path_traversal_marker`, `schema_path_traversal`, `path_traversal_argument_risk`). This is acceptable when multiple layers contributed evidence, but UI should group them by boundary instead of showing a flat noisy list.
- Documentation/search contexts can contain dangerous strings safely. Orthus should distinguish `search_kb`, `search_logs`, `read_documentation`, and `search_code` from action sinks such as file reads, HTTP sends, public comments, shell commands, and database writes.
- Policy reason codes should appear only when policy actually matched the action and should not replace more specific rule/validator reason codes.
- Future cleanup should prefer additive aliases or UI grouping over breaking reason-code renames.

Recommended UI grouping order:
1. decision
2. risk
3. boundary family
4. top 3-5 reason codes
5. matched rules only in debug/local mode

## Known Caveats

- `reason_codes` are explanatory, not exhaustive.
- Multiple reason codes can appear for one decision.
- `debug=false` may hide `matched_rules` but still return `reason_codes`.
- Absence of reason codes on `allow` does not mean zero risk.
- Risk score is advisory; decision is authoritative.

## Debug Behavior

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
