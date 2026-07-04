# CLI Replay Contract

This document defines the v0.2.0 `orthus replay` CLI contract before implementation.

The replay loop is:

```text
validate -> audit snapshot -> replay -> compare -> CI gate
```

## Command Shape

```bash
orthus replay trace.jsonl
orthus replay trace.jsonl --expect expected.jsonl --fail-on-diff
orthus replay trace.jsonl --format table
orthus replay trace.jsonl --format json
orthus replay trace.jsonl --compare all
```

## Flags

Supported flags for v0.2.0:

- `--fail-on-diff`
- `--expect expected.jsonl`
- `--format table|json`
- `--compare decision|reason_codes|fidelity|all`
- `--allow-partial`

Avoid/remove:

- `--fail-on-unexpected-change`

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Pass. |
| `1` | Diff detected. |
| `2` | Invalid trace/schema. |
| `3` | Replay unsupported or required features missing. |
| `4` | Internal replay error. |

## Fidelity

Replay must report one of:

- `full`
- `partial`
- `unsupported`

Replay must never silently treat missing redacted fields as safe.

With `--fail-on-diff`, unsupported replay fails. Partial replay also fails unless `--allow-partial` is set.

## Output Formats

`--format table` is the local human default.

`--format json` is for CI and downstream tooling.

Both formats must include:

- event count
- decision counts
- fidelity counts
- diff count
- unsupported count
- top reason codes
- missing required feature diagnostics when applicable
