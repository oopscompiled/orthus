from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class RulePattern:
    field: str
    regex: str
    flags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RuleSuppressPattern:
    field: str
    regex: str
    flags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Rule:
    id: str
    description: str
    severity: str
    risk: float
    decision_hint: str
    reason_codes: list[str]
    patterns: list[RulePattern]
    suppress_patterns: list[RuleSuppressPattern] = field(default_factory=list)
    required_flags_any: list[str] = field(default_factory=list)
    required_flags_all: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    pack: str = "unknown"


@dataclass(slots=True)
class RuleMatch:
    rule_id: str
    pack: str
    severity: str
    risk: float
    decision_hint: str
    reason_codes: list[str]
    matched_field: str
    matched_text: str
    pattern: str
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RuleSet:
    version: int
    pack: str
    rules: list[Rule]
