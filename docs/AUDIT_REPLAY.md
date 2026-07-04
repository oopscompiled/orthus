# Audit And Replay Design

This document locks the v0.2.0 audit/replay contract before implementation.

v0.2.0 turns Orthus from an action-validation library into a local operator loop for agent security:

```text
validate -> audit snapshot -> replay -> compare -> CI gate
```

The purpose is not forensic evidence. The purpose is local, privacy-safe, git-native regression testing for action-boundary behavior.

## Mission

Orthus should make action-boundary decisions:

- privacy-safe to record
- reproducible through replay
- comparable against expected decisions
- usable as git-native regression tests
- enforceable in CI

Product value:

> Orthus does not merely say `block`. It records a privacy-safe decision snapshot, explains why the action boundary fired, and lets developers replay that decision later as part of normal code review.

## Differentiator

Audit/replay alone is not unique in agent security.

The v0.2.0 differentiator is:

- git-native expected-decision snapshots
- privacy-by-default redaction
- explicit replay fidelity reporting
- CI regression testing for action-boundary behavior
- local/dev-first operation without a hosted dashboard

## Audit Schema v1

All v0.2.0 audit traces must use:

```json
{"schema_version": "orthus.audit.v1"}
```

Recommended JSONL event shape:

```json
{
  "schema_version": "orthus.audit.v1",
  "event_id": "evt_123",
  "timestamp": "2026-07-04T12:00:00Z",
  "actor": {"user_id_hash": "u_7e3", "role": "support_agent"},
  "tool": {"name": "send_email", "category": "external_egress"},
  "source": {"type": "support_ticket", "trust": "untrusted"},
  "args_shape_version": "args_shape.v1",
  "args_shape": {
    "to_domain": "example.com",
    "body_contains_sensitive_marker": true,
    "has_external_url": false
  },
  "feature_manifest": {
    "available_features": [
      "actor.role",
      "tool.name",
      "tool.category",
      "source.trust",
      "args_shape.to_domain",
      "args_shape.body_contains_sensitive_marker"
    ],
    "args_shape_version": "args_shape.v1",
    "redaction_profile": "default.v1",
    "lossy": true,
    "omitted_raw_fields": ["text", "tool_call.args.body", "tool_call.result"]
  },
  "decision": "block",
  "risk": 0.95,
  "reason_codes": ["external_destination", "outbound_content_exfil"],
  "policy_id": "default",
  "session_markers": ["recent_sensitive_read"]
}
```

## Feature Manifest Contract

Every audit event must include a feature manifest.

Required feature manifest fields:

- `available_features`
- `args_shape_version`
- `redaction_profile`
- `lossy`
- `omitted_raw_fields`

The manifest exists because audit traces are privacy-safe and therefore intentionally lossy. Replay must know which redacted features are present before evaluating old traces against new policy/rule expectations.

## Privacy And Redaction Rules

Audit is off by default.

Audit writing is enabled only by:

- `--audit-out <path>`
- `ORTHUS_AUDIT_LOG=<path>`

v0.2.0 writer strategy:

- sync JSONL append
- one event per line
- local filesystem only
- no background queue
- async writer remains P2/backlog

Redaction invariant:

> Redaction failure must never write raw fallback.

Do store:

- event id
- timestamp
- actor role/id hash
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
- feature manifest

Do not store:

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

## Replay Fidelity Contract

Replay classifies each event as exactly one of:

- `full`
- `partial`
- `unsupported`

Definitions:

| Fidelity | Meaning |
|---|---|
| `full` | All required redacted features for the replayed policy/rules are present. |
| `partial` | The trace can be evaluated, but at least one non-critical feature is missing or lossy. |
| `unsupported` | Required features or schema support are missing; replay cannot safely evaluate the event. |

Hard invariant:

> Replay must never silently treat missing redacted fields as safe.

If a policy/rule requires a field that is absent from `available_features`, replay must emit missing-field diagnostics and classify the event as `partial` or `unsupported`.

`--fail-on-diff` behavior:

- fails on decision diffs
- fails on reason-code diffs when reason-code comparison is selected
- fails on unsupported replay
- fails on partial replay unless `--allow-partial` is set

## CLI Contract

Stable command shape:

```bash
orthus replay trace.jsonl
orthus replay trace.jsonl --expect expected.jsonl --fail-on-diff
orthus replay trace.jsonl --format table
orthus replay trace.jsonl --format json
orthus replay trace.jsonl --compare all
```

Keep these flags:

- `--fail-on-diff`
- `--expect expected.jsonl`
- `--format table|json`
- `--compare decision|reason_codes|fidelity|all`
- `--allow-partial`

Avoid/remove:

- `--fail-on-unexpected-change`

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Pass. |
| `1` | Diff detected. |
| `2` | Invalid trace/schema. |
| `3` | Replay unsupported or required features missing. |
| `4` | Internal replay error. |

## Expected-Decision Snapshots

Expected snapshots are git-native JSONL files.

Expected event shape:

```json
{
  "event_id": "evt_123",
  "expect": {
    "decision": "block",
    "reason_codes": ["external_destination", "outbound_content_exfil"],
    "fidelity": "full"
  }
}
```

Comparison modes:

- `decision`
- `reason_codes`
- `fidelity`
- `all`

`all` compares decision, reason codes, and fidelity.

## Schema Migration Policy

Schema rules:

- `schema_version` is required.
- v0.2.0 audit events use `orthus.audit.v1`.
- Support target is current major + previous major once `v2` exists.
- Unsupported schemas fail clearly with exit code `2`.
- Migrations must be registered explicitly in a migrator registry.
- Migrations must not invent security features silently.
- Migrated events must keep a migration note in replay diagnostics.

A migration may rename or reshape fields. It must not create an `available_features` entry for information that was not present in the original trace.

## Fixture Unification

New policy-pack fixtures should be replay-native audit traces.

Target:

```text
tests/fixtures/policies/**/*.jsonl
```

Requirements:

- runnable via `orthus replay`
- include `schema_version: orthus.audit.v1`
- include `feature_manifest`
- include expected decisions either inline or in paired expected snapshot files

Legacy engine fixtures may remain. Do not introduce a second new fixture system.

## CI Replay Mode

CI should be able to run:

```bash
orthus replay tests/fixtures/policies/**/*.jsonl \
  --expect tests/fixtures/policies/expected.jsonl \
  --compare all \
  --fail-on-diff
```

CI output should be stable and reviewable:

```text
events: 128
full: 120
partial: 8
unsupported: 0
allow: 104
log_only: 9
require_approval: 11
block: 4

diffs: 0
```

## Tamper-Evidence Assumption

v0.2.0 local audit logs are debugging/regression artifacts.

They are not tamper-evident forensic evidence against a compromised agent or host.

Out of scope for v0.2.0:

- signed receipts
- hash-chain verification
- out-of-agent writers
- SIEM export
- compliance evidence bundles
- managed evidence retention

Deployment environments remain responsible for local log integrity in v0.2.0.

## P2 / Backlog

- async audit writer
- GitHub Action package
- local review queue prototype
- FastAPI deployment profile
- signed receipts
- hash-chain tamper evidence
- SIEM export
- compliance evidence bundles
