from __future__ import annotations

import json
from pathlib import Path

from api.engine.normalizer import normalize_text

FIXTURES_DIR = Path("tests/fixtures/normalizer")
FIXTURE_FILES = sorted(FIXTURES_DIR.glob("*.jsonl"))

ALLOWED_EXPECT_KEYS = {
    "must_flags",
    "must_not_flags",
    "must_find_decoded",
    "must_not_find_decoded",
    "normalized_contains",
    "normalized_not_contains",
    "max_annotations",
    "changed",
}


def _load_cases() -> list[dict]:
    cases: list[dict] = []
    for file in FIXTURE_FILES:
        for line_no, line in enumerate(file.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            case = json.loads(line)
            case["_source"] = f"{file}:{line_no}"
            cases.append(case)
    return cases


CASES = _load_cases()


def _count_annotations(normalized: str) -> int:
    return normalized.count("[decoded:")


def test_fixture_ids_are_unique() -> None:
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids))


def test_only_allowed_expect_keys() -> None:
    for case in CASES:
        expect = case.get("expect", {})
        unknown = set(expect.keys()) - ALLOWED_EXPECT_KEYS
        assert not unknown, f"Unknown expect keys {unknown} in {case['_source']}"


def test_case_count_targets() -> None:
    assert len(CASES) >= 30
    fp_cases = [
        c
        for c in CASES
        if (c.get("kind") == "safe" and "false_positive" in c.get("attack_type", ""))
        or c.get("id", "").startswith("fp_")
    ]
    assert len(fp_cases) >= 10


def test_normalizer_corpus() -> None:
    for case in CASES:
        result = normalize_text(case["text"])
        expect = case.get("expect", {})

        for flag in expect.get("must_flags", []):
            assert flag in result.flags, f"{case['id']}: missing required flag {flag}"

        for flag in expect.get("must_not_flags", []):
            assert flag not in result.flags, f"{case['id']}: unexpected flag {flag}"

        decoded_values = [finding.decoded for finding in result.findings]

        for needle in expect.get("must_find_decoded", []):
            assert any(needle.lower() in decoded.lower() for decoded in decoded_values), (
                f"{case['id']}: expected decoded fragment {needle!r}"
            )

        for needle in expect.get("must_not_find_decoded", []):
            assert not any(needle.lower() in decoded.lower() for decoded in decoded_values), (
                f"{case['id']}: forbidden decoded fragment {needle!r}"
            )

        for needle in expect.get("normalized_contains", []):
            assert needle in result.normalized, f"{case['id']}: normalized missing {needle!r}"

        for needle in expect.get("normalized_not_contains", []):
            assert needle not in result.normalized, f"{case['id']}: normalized unexpectedly contains {needle!r}"

        if "max_annotations" in expect:
            assert _count_annotations(result.normalized) <= expect["max_annotations"], (
                f"{case['id']}: too many annotations"
            )

        if "changed" in expect:
            assert result.changed is expect["changed"], f"{case['id']}: changed mismatch"
