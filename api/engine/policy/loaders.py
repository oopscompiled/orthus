"""Policy config loaders."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_policy_dict(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("Policy config must be a mapping")
    return config


def load_policy_yaml(path: str) -> dict[str, Any]:
    file = Path(path)
    if not file.exists() or not file.is_file():
        raise ValueError(f"Policy file does not exist or is not a file: {path}")

    data = yaml.safe_load(file.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Policy YAML root must be a mapping")
    return data
