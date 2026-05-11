"""Data models for normalizer outputs."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class DecodeFinding:
    kind: str
    original: str
    decoded: str
    confidence: float


@dataclass(slots=True)
class NormalizationResult:
    original: str
    normalized: str
    findings: list[DecodeFinding] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    changed: bool = False
