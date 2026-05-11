from __future__ import annotations

from .models import Rule, RuleMatch


def match_rule_text(rule: Rule, text: str) -> list[RuleMatch]:
    if not rule.compiled_pattern:
        return []
    matches: list[RuleMatch] = []
    for m in rule.compiled_pattern.finditer(text):
        matched_text = m.group(0)
        matches.append(
            RuleMatch(
                rule_id=rule.id,
                name=rule.name,
                category=rule.category,
                severity=rule.severity,
                confidence=rule.confidence,
                reason_code=rule.reason_code,
                matched_text=matched_text,
                evidence={"span": [m.start(), m.end()]},
            )
        )
    return matches
