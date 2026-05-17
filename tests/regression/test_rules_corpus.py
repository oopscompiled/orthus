from __future__ import annotations

import json
from pathlib import Path

from api.engine.normalizer import normalize_text
from api.engine.rules import RulesEngine, load_builtin_basic_rules

FIXTURE_FILES = sorted(Path("tests/fixtures/rules").glob("*.jsonl"))


def _load_cases() -> list[dict]:
    cases: list[dict] = []
    for f in FIXTURE_FILES:
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                cases.append(json.loads(line))
    return cases


CASES = _load_cases()
ENGINE = RulesEngine(load_builtin_basic_rules())


def _reason_codes(matches) -> list[str]:
    out: list[str] = []
    for m in matches:
        for rc in m.reason_codes:
            if rc not in out:
                out.append(rc)
    return out


def test_rules_corpus() -> None:
    for case in CASES:
        case_id = case.get("id", "<no-id>")
        text = case.get("text", case.get("input"))
        assert isinstance(text, str), f"{case_id}: missing text/input"

        n = normalize_text(text)
        matches = ENGINE.scan(n)
        ids = [m.rule_id for m in matches]
        reasons = _reason_codes(matches)
        max_risk = max((m.risk for m in matches), default=0.0)
        exp = case.get("expect_basic") or case.get("expect", {})

        if not exp:
            exp = {
                "must_match": case.get("expect_match", []),
                "must_not_match": case.get("expect_no_match", []),
            }

        for rid in exp.get("must_match", []):
            assert rid in ids, f"{case_id}: missing match {rid}"

        for rid in exp.get("must_not_match", []):
            assert rid not in ids, f"{case_id}: unexpected match {rid}"

        for rc in exp.get("must_reason_codes", []):
            assert rc in reasons, f"{case_id}: missing reason {rc}"

        for rc in exp.get("must_not_reason_codes", []):
            assert rc not in reasons, f"{case_id}: unexpected reason {rc}"

        if "min_risk" in exp:
            assert max_risk >= float(exp["min_risk"]), f"{case_id}: risk too low"
        if "max_risk" in exp:
            assert max_risk <= float(exp["max_risk"]), f"{case_id}: risk too high"
        if "max_matches" in exp:
            assert len(matches) <= int(exp["max_matches"]), f"{case_id}: too many matches"

        expected_decision = case.get("expect_decision")
        if expected_decision == "allow":
            assert not matches, f"{case_id}: expected no matches for allow"
