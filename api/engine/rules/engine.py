from __future__ import annotations

import re
from collections.abc import Iterable

from api.engine.normalizer import NormalizationResult

from .models import Rule, RuleMatch, RulePattern, RuleSet

FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}

FIELD_PRIORITY = {
    "normalized": 0,
    "findings.decoded": 1,
    "original": 2,
    "findings.original": 3,
}


def _compile(regex: str, flags: list[str]) -> re.Pattern[str]:
    bitmask = re.IGNORECASE
    for f in flags:
        bitmask |= FLAG_MAP[f]
    try:
        return re.compile(regex, bitmask)
    except re.error as exc:
        raise ValueError(f"Invalid regex: {regex!r}") from exc


def _build_fields(normalization: NormalizationResult) -> dict[str, list[str]]:
    return {
        "original": [normalization.original],
        "normalized": [normalization.normalized],
        "findings.decoded": [f.decoded for f in normalization.findings],
        "findings.original": [f.original for f in normalization.findings],
        "flags": [" ".join(normalization.flags)],
    }


class RulesEngine:
    def __init__(self, rule_sets: list[RuleSet]):
        self.rule_sets = rule_sets
        self.rules: list[Rule] = [rule for rs in rule_sets for rule in rs.rules]
        self._compiled: dict[tuple[str, str, str], re.Pattern[str]] = {}
        for rule in self.rules:
            for p in rule.patterns:
                self._compiled[(rule.id, "pattern", p.regex)] = _compile(p.regex, p.flags)
            for p in rule.suppress_patterns:
                self._compiled[(rule.id, "suppress", p.regex)] = _compile(p.regex, p.flags)

    def _required_flags_ok(self, rule: Rule, flags: list[str]) -> bool:
        flag_set = set(flags)
        if rule.required_flags_all and not all(flag in flag_set for flag in rule.required_flags_all):
            return False
        if rule.required_flags_any and not any(flag in flag_set for flag in rule.required_flags_any):
            return False
        return True

    def _suppress_match(self, rule: Rule, fields: dict[str, list[str]]) -> bool:
        for sup in rule.suppress_patterns:
            values = fields.get(sup.field, [])
            cre = self._compiled[(rule.id, "suppress", sup.regex)]
            if any(cre.search(value) for value in values):
                return True
        return False

    def _rule_matches(self, rule: Rule, fields: dict[str, list[str]]) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for pat in rule.patterns:
            values = fields.get(pat.field, [])
            cre = self._compiled[(rule.id, "pattern", pat.regex)]
            for value in values:
                for m in cre.finditer(value):
                    matches.append(
                        RuleMatch(
                            rule_id=rule.id,
                            pack=rule.pack,
                            severity=rule.severity,
                            risk=rule.risk,
                            decision_hint=rule.decision_hint,
                            reason_codes=list(rule.reason_codes),
                            matched_field=pat.field,
                            matched_text=m.group(0),
                            pattern=pat.regex,
                            tags=list(rule.tags),
                        )
                    )
        return matches

    def scan(self, normalization: NormalizationResult) -> list[RuleMatch]:
        fields = _build_fields(normalization)
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if not self._required_flags_ok(rule, normalization.flags):
                continue
            if self._suppress_match(rule, fields):
                continue
            matches.extend(self._rule_matches(rule, fields))

        # Keep only one match per rule_id with best score/tie-break by field priority.
        best_by_rule: dict[str, RuleMatch] = {}
        for m in matches:
            current = best_by_rule.get(m.rule_id)
            if current is None:
                best_by_rule[m.rule_id] = m
                continue

            if m.risk > current.risk:
                best_by_rule[m.rule_id] = m
                continue

            if m.risk < current.risk:
                continue

            current_priority = FIELD_PRIORITY.get(current.matched_field, 99)
            next_priority = FIELD_PRIORITY.get(m.matched_field, 99)
            if next_priority < current_priority:
                best_by_rule[m.rule_id] = m

        deduped = list(best_by_rule.values())

        # If a "soft" rule family has a corresponding non-soft hit, keep only non-soft.
        non_soft_ids = {m.rule_id for m in deduped if not m.rule_id.endswith("_soft")}
        filtered: list[RuleMatch] = []
        for m in deduped:
            if m.rule_id.endswith("_soft"):
                base_id = m.rule_id[: -len("_soft")]
                if base_id in non_soft_ids:
                    continue
            filtered.append(m)

        filtered.sort(key=lambda m: (-m.risk, m.rule_id))
        return filtered
