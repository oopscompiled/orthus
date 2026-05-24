# Rule Pack Boundary: Public/Basic vs Private/Intelligence

## Purpose
This document defines the open-core boundary for rule packs in Orthus.

## Public/Basic Rules
Public/basic rules should stay:
- deterministic
- stable across releases
- widely known and explainable
- high precision
- low maintenance

Typical public/basic examples:
- `ignore previous instructions`
- `reveal system prompt`
- `eval/exec/os.system`
- `curl | sh` / `wget | bash`
- `/etc/passwd` / `.ssh` / `.env`
- obvious external token exfiltration
- hidden MCP directives

## Private/Pro Intelligence
Private/pro intelligence is usually:
- evolving and research-derived
- customer/log-derived
- semantic rewrite heavy
- calibration-heavy and high-FP-sensitive
- expensive to maintain

Typical private/pro examples:
- diagnostic tunnel abuse
- telemetry collector abuse
- maintenance hook abuse
- analytics export abuse
- VIP exception abuse
- temporary audit exclude abuse
- tool shadowing / MCP rug-pull patterns
- semantic exfiltration and multi-step intent
- customer-derived incident signatures

## Repository Rule-Pack Scope
This public repository keeps only `basic` packs under:
- `api/engine/rules/packs/basic/`

No proprietary packs are committed here.

## Extension Point
`RulesEngine` can be initialized with externally loaded packs. For example:

```python
from pathlib import Path
from api.engine.rules import RulesEngine, load_rule_packs

def yaml_files(directory: str) -> list[str]:
    return [str(p) for p in sorted(Path(directory).glob("*.yaml"))]

packs = load_rule_packs(
    yaml_files("api/engine/rules/packs/basic")
    + yaml_files("/opt/aaf/intel/packs/pro")
)
engine = RulesEngine(packs)
```

The `/opt/aaf/intel/packs/pro` path is an example only and is not part of this repo.

## Testing Boundary
Fixture metadata can classify cases by tier:
- `tier: "basic"`
- `tier: "pro_candidate"`
- `tier: "private_intel"`

For public CI:
- enforce only `expect_basic`
- `expect_pro` is informational for future private intelligence evaluation
