from __future__ import annotations

from collections.abc import Iterable
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

import yaml

from .models import Rule, RulePattern, RuleSet, RuleSuppressPattern

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_DECISION_HINTS = {"log_only", "allow", "block", "require_approval", "redact", "sandbox"}
VALID_FLAGS = {"IGNORECASE", "MULTILINE", "DOTALL"}


def _validate_flags(flags: list[str]) -> None:
    bad = [f for f in flags if f not in VALID_FLAGS]
    if bad:
        raise ValueError(f"Invalid regex flags: {bad}")


def _load_pattern(raw: dict, kind: str) -> RulePattern | RuleSuppressPattern:
    if not isinstance(raw, dict):
        raise ValueError(f"{kind} entry must be mapping")
    field = raw.get("field")
    regex = raw.get("regex")
    flags = list(raw.get("flags", []))
    if not field or not regex:
        raise ValueError(f"{kind} must include field and regex")
    _validate_flags(flags)
    if kind == "pattern":
        return RulePattern(field=field, regex=regex, flags=flags)
    return RuleSuppressPattern(field=field, regex=regex, flags=flags)


def _load_rule(raw: dict, pack: str) -> Rule:
    required = ["id", "description", "severity", "risk", "decision_hint", "reason_codes", "match"]
    missing = [k for k in required if k not in raw]
    if missing:
        raise ValueError(f"Rule missing required fields: {missing}")

    severity = str(raw["severity"])
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity}")

    decision_hint = str(raw["decision_hint"])
    if decision_hint not in VALID_DECISION_HINTS:
        raise ValueError(f"Invalid decision_hint: {decision_hint}")

    risk = float(raw["risk"])
    if risk < 0.0 or risk > 1.0:
        raise ValueError(f"risk must be between 0.0 and 1.0 for {raw['id']}")

    match = raw["match"]
    if not isinstance(match, dict) or "any" not in match or not isinstance(match["any"], list):
        raise ValueError(f"Rule {raw['id']} must define match.any list")
    patterns = [_load_pattern(item, "pattern") for item in match["any"]]

    suppress_patterns: list[RuleSuppressPattern] = []
    suppress_if = raw.get("suppress_if")
    if suppress_if:
        if not isinstance(suppress_if, dict) or "any" not in suppress_if or not isinstance(suppress_if["any"], list):
            raise ValueError(f"Rule {raw['id']} suppress_if must define any list")
        suppress_patterns = [_load_pattern(item, "suppress") for item in suppress_if["any"]]  # type: ignore[list-item]

    requires = raw.get("requires", {})
    if not isinstance(requires, dict):
        raise ValueError(f"Rule {raw['id']} requires must be mapping")

    return Rule(
        id=str(raw["id"]),
        description=str(raw["description"]),
        severity=severity,
        risk=risk,
        decision_hint=decision_hint,
        reason_codes=[str(x) for x in raw["reason_codes"]],
        patterns=patterns,
        suppress_patterns=suppress_patterns,
        required_flags_any=[str(x) for x in requires.get("any_flags", [])],
        required_flags_all=[str(x) for x in requires.get("all_flags", [])],
        tags=[str(x) for x in raw.get("tags", [])],
        pack=pack,
    )


def load_rule_pack(path: str | Path) -> RuleSet:
    file = Path(path)
    if not file.exists() or not file.is_file():
        raise ValueError(f"Rule pack path does not exist or is not file: {file}")
    content = yaml.safe_load(file.read_text(encoding="utf-8"))
    if not isinstance(content, dict):
        raise ValueError(f"Invalid YAML root in {file}")

    version = int(content.get("version", 1))
    pack = str(content.get("pack", file.stem))
    raw_rules = content.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError(f"rules must be list in {file}")

    rules = [_load_rule(raw, pack=pack) for raw in raw_rules]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError(f"Duplicate rule IDs inside {file}")

    return RuleSet(version=version, pack=pack, rules=rules)


def load_rule_packs(paths: Iterable[str | Path]) -> list[RuleSet]:
    sets = [load_rule_pack(path) for path in paths]
    all_ids = [rule.id for rs in sets for rule in rs.rules]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("Duplicate rule IDs across rule packs")
    return sets


def load_builtin_basic_rules() -> list[RuleSet]:
    packs_dir = resources.files("api.engine.rules").joinpath("packs/basic")
    entries: list[Traversable] = sorted(
        (item for item in packs_dir.iterdir() if item.is_file() and item.name.endswith(".yaml")),
        key=lambda item: item.name,
    )

    rule_sets: list[RuleSet] = []
    for entry in entries:
        with resources.as_file(entry) as file_path:
            rule_sets.append(load_rule_pack(file_path))

    all_ids = [rule.id for rs in rule_sets for rule in rs.rules]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("Duplicate rule IDs across rule packs")
    return rule_sets


class RulesLoader:
    """Compatibility loader facade for simple pack-based loading."""

    def load_pack(self, pack: str) -> list[Rule]:
        if pack != "basic":
            raise ValueError(f"Unsupported pack: {pack}")
        rule_sets = load_builtin_basic_rules()
        return [rule for rs in rule_sets for rule in rs.rules]
