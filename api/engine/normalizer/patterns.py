"""Compiled regex patterns used by normalizer internals."""

from __future__ import annotations

import re

from .config import (
    IGNORE_LIKE_VERBS,
    OBFUSCATION_SEPARATOR_PATTERN,
    POLICY_OBJECTS,
    SUSPICIOUS_WORDS,
)

ASCII_CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
UNICODE_SPACE_PATTERN = re.compile(r"[\s\u00a0\u1680\u180e\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+")
URL_TOKEN_PATTERN = re.compile(r"\S*%(?:[0-9a-fA-F]{2})\S*")
UNICODE_ESCAPE_PATTERN = re.compile(r"(?<!\\)(?:\\u[0-9a-fA-F]{4})+")
DOUBLE_UNICODE_ESCAPE_PATTERN = re.compile(r"(?:\\\\u[0-9a-fA-F]{4})+")
UPPER_UNICODE_ESCAPE_PATTERN = re.compile(r"(?<!\\)(?:\\U[0-9a-fA-F]{8})+")
DOUBLE_UPPER_UNICODE_ESCAPE_PATTERN = re.compile(r"(?:\\\\U[0-9a-fA-F]{8})+")
OCTAL_ESCAPE_PATTERN = re.compile(r"(?:\\[0-7]{3}){2,}")
HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
STRING_CONCAT_PATTERN = re.compile(r"""((?:'[^'\\]*'|"[^"\\]*")(?:\s*\+\s*(?:'[^'\\]*'|"[^"\\]*")){1,})""")
UTF7_SEQUENCE_PATTERN = re.compile(r"((?:\+[A-Za-z0-9/]+-)(?:[\s._-]+\+[A-Za-z0-9/]+-)+)")
BASE64_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
SEGMENTED_BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{4,}(?:[._\-][A-Za-z0-9+/]{4,}){1,}={0,2})(?![A-Za-z0-9+/=])")
SPACE_SEGMENTED_BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{8,}(?: [A-Za-z0-9+/]{8,}){1,}={0,2})(?![A-Za-z0-9+/=])")
HEX_TOKEN_PATTERN = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{16,})(?![A-Fa-f0-9])")
SPACED_HEX_TOKEN_PATTERN = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{2,}(?:\s+[A-Fa-f0-9]{2,})+)(?![A-Fa-f0-9])")


def _alternation(values: list[str]) -> str:
    return "|".join(re.escape(value) for value in sorted(values, key=len, reverse=True))


def build_suspicious_command_patterns() -> list[re.Pattern[str]]:
    return [
        re.compile(
            rf"\b(?:{_alternation(IGNORE_LIKE_VERBS)})\b"
            rf".{{0,60}}"
            rf"\b(?:{_alternation(POLICY_OBJECTS)})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bpay\s+no\s+attention\s+to\b"
            r".{0,60}"
            r"\b(?:previous instructions|prior instructions|earlier instructions|system prompt|system message|developer message|rules|policy|guardrails)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\btake\s+no\s+notice\s+of\b"
            r".{0,60}"
            r"\b(?:previous instructions|prior instructions|earlier instructions|system prompt|system message|developer message|rules|policy|guardrails)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bturn\s+a\s+blind\s+eye\s+to\b"
            r".{0,60}"
            r"\b(?:previous instructions|prior instructions|earlier instructions|system prompt|system message|developer message|rules|policy|guardrails)\b",
            re.IGNORECASE,
        ),
    ]


def build_obfuscation_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return [
        (
            word,
            re.compile(
                rf"(?<![A-Za-z0-9])"
                rf"{OBFUSCATION_SEPARATOR_PATTERN.join(re.escape(ch) for ch in word)}"
                rf"(?![A-Za-z0-9])",
                re.IGNORECASE,
            ),
        )
        for word in SUSPICIOUS_WORDS
    ]


SUSPICIOUS_COMMAND_PATTERNS = build_suspicious_command_patterns()
OBFUSCATION_PATTERNS = build_obfuscation_patterns()
