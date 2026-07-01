# Audit And Replay Design

This is a design note for local Orthus audit/replay workflows. It is not a new runtime storage feature.

Orthus should make action decisions explainable without storing raw sensitive data.

## Goal

Help developers answer:

- What action was proposed?
- Who proposed it?
- What trust boundary was crossed?
- Which policy/rules contributed?
- What decision did Orthus return?
- Would a policy change alter historical decisions?

## Target Audit Record

Recommended fields:

```json
{
  "event_id": "evt_123",
  "timestamp": "2026-07-01T12:00:00Z",
  "actor": {"user_id": "support_1", "role": "support_agent"},
  "tool": {"name": "send_email", "category": "external_egress"},
  "source": {"type": "support_ticket", "trust": "untrusted"},
  "redacted_args_shape": {
    "to_domain": "example.com",
    "body_contains_sensitive_marker": true
  },
  "decision": "block",
  "risk": 0.95,
  "reason_codes": ["external_destination", "outbound_content_exfil"],
  "policy_id": "default",
  "session_markers": ["recent_sensitive_read"]
}
```

## Do Store

- event id
- timestamp
- actor role/id
- tool name/category
- redacted args shape
- source trust/type
- destination class/domain when safe to store
- decision
- risk
- reason codes
- policy id/version
- matched rule IDs in local debug mode
- session markers/signatures/counters
- compact provenance references

## Do Not Store

- raw prompts
- raw tool outputs
- raw auth headers
- raw secrets
- raw sensitive URLs
- private logs
- full customer records
- full files
- long unredacted request/response bodies

If a value is needed for replay, prefer a marker, hash, scope label, or synthetic fixture value.

## Replay Input Sketch

Future replay files can be JSONL action events:

```jsonl
{"event_id":"evt_1","actor":{"role":"support_agent"},"tool_call":{"name":"search_tickets","args":{"query":"refund delay"}},"source_trust":"trusted"}
{"event_id":"evt_2","actor":{"role":"support_agent"},"tool_call":{"name":"export_customer_data","args":{"scope":"all"}},"source_trust":"untrusted"}
```

Potential command:

```bash
orthus replay trace.jsonl --policy policy.yaml
```

If a CLI does not exist yet, an interim script can follow this shape:

```bash
uv run python evals/replay_actions.py --events examples/traces/*.jsonl --policy policy.yaml
```

## Replay Output Sketch

```text
events: 128
allow: 104
log_only: 9
require_approval: 11
block: 4

top reason codes:
- external_egress_after_sensitive_read
- mcp_tool_description_changed
- prod_shell_requires_review
```

## Privacy And Safety Constraints

Audit/replay must follow the same bounded-state doctrine as CERBER:

> Store signatures, markers, counters, and bounded provenance; do not store raw traces.

Replay should be useful for policy tuning and regression testing, not a sensitive-data warehouse.

## Open Questions

- exact JSONL replay schema
- local CLI name and flags
- whether replay should support stateful session grouping by default
- how to redact application-specific fields consistently
- whether to emit SARIF/JUnit/CI-friendly reports later
