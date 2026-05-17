"""Canonical text cleanup helpers for normalization."""

from __future__ import annotations

import re
import unicodedata

from .config import CYRILLIC_CONFUSABLES, FORMAT_CHARS_TO_REMOVE, SUSPICIOUS_COMPOUND_REPAIRS, UNICODE_PUNCTUATION_TRANSLATION
from .patterns import OBFUSCATION_PATTERNS, ASCII_CONTROL_PATTERN, UNICODE_SPACE_PATTERN


def apply_nfkc(text: str) -> tuple[str, bool]:
    normalized = unicodedata.normalize("NFKC", text)
    return normalized, normalized != text


def remove_zero_width(text: str) -> tuple[str, bool]:
    cleaned = "".join(
        char
        for char in text
        if char not in FORMAT_CHARS_TO_REMOVE and not (0xE0000 <= ord(char) <= 0xE007F)
    )
    return cleaned, cleaned != text


def remove_control_chars(text: str) -> tuple[str, bool]:
    cleaned = ASCII_CONTROL_PATTERN.sub(" ", text)
    return cleaned, cleaned != text


def remove_combining_marks_after_ascii(text: str) -> tuple[str, bool]:
    out: list[str] = []
    changed = False
    prev_ascii_alnum = False
    for ch in text:
        if unicodedata.combining(ch) and prev_ascii_alnum:
            changed = True
            continue
        out.append(ch)
        prev_ascii_alnum = ch.isascii() and ch.isalnum()
    return "".join(out), changed


def canonicalize_whitespace(text: str) -> tuple[str, bool]:
    collapsed = UNICODE_SPACE_PATTERN.sub(" ", text).strip()
    return collapsed, collapsed != text


def canonicalize_unicode_punctuation(text: str) -> tuple[str, bool]:
    translated = text.translate(str.maketrans(UNICODE_PUNCTUATION_TRANSLATION))
    return translated, translated != text


def repair_suspicious_compounds(text: str) -> tuple[str, bool]:
    changed = False
    repaired = text
    for compound, replacement in SUSPICIOUS_COMPOUND_REPAIRS.items():
        pattern = re.compile(re.escape(compound), re.IGNORECASE)
        repaired_new, count = pattern.subn(replacement, repaired)
        if count:
            changed = True
            repaired = repaired_new
    return repaired, changed


def collapse_suspicious_obfuscation(text: str) -> tuple[str, bool]:
    changed = False
    for word, pattern in OBFUSCATION_PATTERNS:
        text, count = pattern.subn(word, text)
        if count:
            changed = True
    return text, changed


def contains_mixed_latin_cyrillic(text: str) -> bool:
    has_latin = any("LATIN" in unicodedata.name(char, "") for char in text if char.isalpha())
    has_cyrillic = any("CYRILLIC" in unicodedata.name(char, "") for char in text if char.isalpha())
    return has_latin and has_cyrillic


def generate_confusable_skeleton(text: str) -> tuple[str, bool]:
    skeleton = "".join(CYRILLIC_CONFUSABLES.get(ch, ch) for ch in text)
    return skeleton, skeleton != text
