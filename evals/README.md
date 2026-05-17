# Evals Harness

Local corpus evaluation harness for Orthus deterministic pipeline.

## Purpose

Run JSONL fixtures through `FirewallEngine` and produce actionable pass/fail reports.

## Run

Basic corpus:

```bash
uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline
```

Stateful corpus:

```bash
uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline_stateful --stateful
```

Safe false-positive corpus:

```bash
uv run python evals/run_corpus.py --corpus tests/fixtures/safe_fp --kind safe_fp
```

Pro candidates (no fail):

```bash
uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline --tier pro_candidate --no-fail
```

JSON output:

```bash
uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline --json
```

Write report:

```bash
uv run python evals/run_corpus.py --corpus tests/fixtures/pipeline --output evals/reports/latest.json
```

## Fixture workflow

1. Add adversarial/safe case to JSONL.
2. Classify case as:
- basic deterministic gap
- policy gap
- stateful/session gap
- pro candidate semantic gap
- safe false-positive guard
3. Add expectation fields.
4. Run eval harness.
5. Patch only if case belongs in deterministic basic path.
6. Keep semantic/pro candidates without forcing over-broad basic rules.

Every new broad rule should include at least one `safe_fp` fixture.

## Notes

- Harness executes only through `FirewallEngine`.
- No model, no network, no external services.
- `--no-fail` is useful during exploratory corpus expansion.
