# Architecture

Orthus evaluates AI-agent actions with a deterministic fast path before execution.

## Pipeline

```text
request
  -> normalizer      (text/encoding canonicalization)
  -> rules           (YAML signatures + structural validators)
  -> policy          (developer-owned action policy)
  -> decision        (shared aggregation contract)
  -> cerber          (stateful session trajectory risk)
  -> final decision
```

## Layer Contract

- `normalizer`: reveals hidden text (encodings/obfuscation), emits flags/findings.
- `rules`: matches known high-precision attack patterns and structural tool risks.
- `policy`: enforces application-specific approval/block constraints.
- `decision`: deterministic aggregation of policy/rules outputs.
- `cerber`: stateful sequence/session risk upgrades (e.g. repeated probes, lifecycle chains).

## Output Shape

All flows converge to one decision object (via `FirewallResult`) with:
- decision
- risk
- reason codes
- matched rules
- updated session context

This is the contract future API endpoints should expose.
