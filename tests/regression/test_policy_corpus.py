from __future__ import annotations

import json
from pathlib import Path

from api.engine.policy.engine import PolicyEngine


def _load_cases(path: Path) -> list[dict]:
    cases: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cases.append(json.loads(line))
    return cases


ENGINE = PolicyEngine.from_yaml("tests/fixtures/policy/test_policy.yaml")
CASES = _load_cases(Path("tests/fixtures/policy/policy_cases.jsonl"))


def test_policy_corpus() -> None:
    for case in CASES:
        result = ENGINE.evaluate(
            case["action"],
            args=case.get("args", {}),
            actor=case.get("actor", {}),
            session=case.get("session", {}),
        )
        assert result.decision == case.get("expect_decision"), case.get("note", "policy case failed")
