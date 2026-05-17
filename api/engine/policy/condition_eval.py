"""Deterministic safe evaluator for simple policy conditions."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import yaml

_CONDITION_PATTERN = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*(contains|not_in|in|==|!=|>=|<=|>|<)\s*(.+?)\s*$")


def _resolve_path(path: str, context: Mapping[str, Any]) -> tuple[bool, Any]:
    parts = path.split(".")
    current: Any = context
    for part in parts:
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _parse_literal(raw: str) -> Any:
    value = raw.strip()
    if value.lower() == "none":
        return None
    return yaml.safe_load(value)


def eval_condition(condition: str, context: Mapping[str, Any]) -> bool:
    """Evaluate a condition string safely.

    Fail-open behavior: unparseable conditions return False.
    """
    match = _CONDITION_PATTERN.match(condition)
    if not match:
        return False

    left_path, op, right_raw = match.groups()
    found, left_value = _resolve_path(left_path, context)
    if not found:
        return False

    try:
        right_value = _parse_literal(right_raw)
    except yaml.YAMLError:
        return False

    try:
        if op == "==":
            return left_value == right_value
        if op == "!=":
            return left_value != right_value
        if op == ">":
            return left_value > right_value
        if op == ">=":
            return left_value >= right_value
        if op == "<":
            return left_value < right_value
        if op == "<=":
            return left_value <= right_value
        if op == "in":
            return left_value in right_value
        if op == "not_in":
            return left_value not in right_value
        if op == "contains":
            if isinstance(left_value, str) and isinstance(right_value, str):
                return right_value in left_value
            if isinstance(left_value, list):
                return right_value in left_value
            return False
    except (TypeError, ValueError):
        return False

    return False
