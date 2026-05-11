"""Deterministic decode-confidence scoring (not risk/policy decisions)."""

from __future__ import annotations

import unicodedata

from .config import BASE_CONFIDENCE, ENCODING_CONTEXT_MARKERS, SUSPICIOUS_PHRASES, SUSPICIOUS_WORDS
from .patterns import SUSPICIOUS_COMMAND_PATTERNS


def contains_suspicious_keyword(text: str) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in SUSPICIOUS_WORDS)


def contains_suspicious_phrase(text: str) -> bool:
    lowered = " ".join(text.lower().split())
    return any(phrase in lowered for phrase in SUSPICIOUS_PHRASES)


def contains_suspicious_command_pattern(text: str) -> bool:
    normalized = " ".join(text.lower().split())
    return any(pattern.search(normalized) for pattern in SUSPICIOUS_COMMAND_PATTERNS)


def _has_encoding_context(context: str) -> bool:
    lowered = context.lower()
    return any(marker in lowered for marker in ENCODING_CONTEXT_MARKERS)


def _looks_like_benign_reference_context(context: str) -> bool:
    lowered = context.lower()
    return any(
        marker in lowered
        for marker in (
            "ref-",
            "reference",
            "report is available",
            "todo",
            "verify",
        )
    )


def _count_control_chars(text: str) -> int:
    return sum(1 for char in text if unicodedata.category(char)[0] == "C")


def extract_context_window(text: str, original: str, radius: int = 40) -> str:
    idx = text.lower().find(original.lower())
    if idx == -1:
        return text[: radius * 2]

    start = max(0, idx - radius)
    end = min(len(text), idx + len(original) + radius)
    return text[start:end]


def score_decoding_confidence(
    *,
    kind: str,
    original: str,
    decoded: str,
    round_index: int = 0,
    context: str = "",
    was_segmented: bool = False,
) -> float:
    score = BASE_CONFIDENCE.get(kind, 0.60)

    if contains_suspicious_keyword(decoded):
        score += 0.15

    if contains_suspicious_phrase(decoded):
        score += 0.10

    if contains_suspicious_command_pattern(decoded):
        score += 0.20

    if _has_encoding_context(context):
        score += 0.10

    if round_index > 0:
        score += 0.10

    if was_segmented:
        score += 0.05

    if kind == "base64" and len(original.strip("=")) < 12:
        score -= 0.20

    if decoded != decoded.strip():
        score -= 0.15

    if "\ufffd" in decoded:
        score -= 0.20

    if _count_control_chars(decoded) > 0:
        score -= 0.10

    if len(decoded.split()) == 1 and len(decoded) <= 8:
        score -= 0.15

    if _looks_like_benign_reference_context(context):
        score -= 0.10

    return round(max(0.0, min(1.0, score)), 2)
