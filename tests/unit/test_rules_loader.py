from __future__ import annotations

from pathlib import Path

import pytest

from api.engine.rules import RulesEngine, load_builtin_basic_rules, load_rule_pack


def test_load_builtin_basic_rules_returns_non_empty() -> None:
    sets = load_builtin_basic_rules()
    assert sets
    assert any(rs.rules for rs in sets)


def test_invalid_yaml_raises_value_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("not: [valid", encoding="utf-8")
    with pytest.raises(Exception):
        load_rule_pack(p)


def test_loaded_rule_core_fields_present() -> None:
    sets = load_builtin_basic_rules()
    for rs in sets:
        for rule in rs.rules:
            assert rule.id
            assert rule.severity
            assert 0.0 <= rule.risk <= 1.0
            assert rule.decision_hint
            assert rule.reason_codes


def test_invalid_regex_raises_clear_error(tmp_path: Path) -> None:
    p = tmp_path / "bad_regex.yaml"
    p.write_text(
        """
version: 1
pack: x
rules:
  - id: x.bad
    description: bad
    severity: low
    risk: 0.2
    decision_hint: log_only
    reason_codes: [x]
    match:
      any:
        - field: normalized
          regex: "("
""",
        encoding="utf-8",
    )
    rs = load_rule_pack(p)
    with pytest.raises(ValueError):
        RulesEngine([rs])
