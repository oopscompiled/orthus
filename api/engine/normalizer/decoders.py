"""Deterministic decoder helpers used by the normalizer pipeline."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from urllib.parse import unquote

from .models import DecodeFinding
from .config import FORMAT_CHARS_TO_REMOVE
from .patterns import (
    BASE64_TOKEN_PATTERN,
    DOUBLE_UPPER_UNICODE_ESCAPE_PATTERN,
    HEX_ESCAPE_PATTERN,
    HEX_TOKEN_PATTERN,
    OCTAL_ESCAPE_PATTERN,
    SEGMENTED_BASE64_PATTERN,
    SPACE_SEGMENTED_BASE64_PATTERN,
    STRING_CONCAT_PATTERN,
    UPPER_UNICODE_ESCAPE_PATTERN,
    UTF7_SEQUENCE_PATTERN,
    URL_TOKEN_PATTERN,
)
from .scoring import contains_suspicious_keyword, contains_suspicious_phrase


def _is_mostly_printable(value: str, threshold: float = 0.7) -> bool:
    if not value:
        return False

    printable = 0
    for char in value:
        if char in "\n\r\t" or unicodedata.category(char)[0] != "C":
            printable += 1

    return (printable / len(value)) >= threshold


def _looks_safe_decoded_text(value: str) -> bool:
    return _is_mostly_printable(value) and "\ufffd" not in value and bool(value.strip())


def _looks_safe_decoded_text_allow_whitespace(value: str) -> bool:
    return _is_mostly_printable(value) and "\ufffd" not in value and bool(value)


def decode_unicode_like(text: str, pattern: re.Pattern[str], kind: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        compact = token.replace("\\\\u", "\\u").replace("\\\\U", "\\U")

        try:
            decoded = compact.encode("utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return token

        if decoded == token:
            return token

        if decoded in FORMAT_CHARS_TO_REMOVE:
            findings.append(
                DecodeFinding(
                    kind=kind,
                    original=token,
                    decoded=decoded,
                    confidence=0.0,
                )
            )
            return decoded

        if _looks_safe_decoded_text_allow_whitespace(decoded):
            findings.append(
                DecodeFinding(
                    kind=kind,
                    original=token,
                    decoded=decoded,
                    confidence=0.0,
                )
            )
            return decoded

        return token

    return pattern.sub(replacer, text), findings


def decode_url_segments(text: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        decoded = unquote(token)

        if decoded != token and _looks_safe_decoded_text(decoded):
            findings.append(
                DecodeFinding(
                    kind="url",
                    original=token,
                    decoded=decoded,
                    confidence=0.0,
                )
            )
            return decoded

        return token

    return URL_TOKEN_PATTERN.sub(replacer, text), findings


def decode_octal_escapes(text: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def replacer(match: re.Match[str]) -> str:
        token = match.group(0)

        try:
            decoded = bytes(int(octet, 8) for octet in token.split("\\")[1:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return token

        if _looks_safe_decoded_text_allow_whitespace(decoded):
            findings.append(
                DecodeFinding(
                    kind="octal_escape",
                    original=token,
                    decoded=decoded,
                    confidence=0.0,
                )
            )
            return decoded

        return token

    return OCTAL_ESCAPE_PATTERN.sub(replacer, text), findings


def decode_hex_escapes(text: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        parts = re.findall(r"\\x([0-9a-fA-F]{2})", token)

        try:
            decoded = bytes(int(part, 16) for part in parts).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return token

        if _looks_safe_decoded_text_allow_whitespace(decoded):
            findings.append(
                DecodeFinding(
                    kind="hex_escape",
                    original=token,
                    decoded=decoded,
                    confidence=0.0,
                )
            )
            return decoded

        return token

    return HEX_ESCAPE_PATTERN.sub(replacer, text), findings


def collapse_string_concat(text: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def replacer(match: re.Match[str]) -> str:
        token = match.group(1)
        parts = re.findall(r"'([^'\\]*)'|\"([^\"\\]*)\"", token)
        values = [(a if a else b) for a, b in parts]
        collapsed = "".join(values)

        if not collapsed:
            return token

        findings.append(
            DecodeFinding(
                kind="string_concat",
                original=token,
                decoded=collapsed,
                confidence=0.0,
            )
        )

        return token

    return STRING_CONCAT_PATTERN.sub(replacer, text), findings


def decode_utf7_sequences(text: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def decode_chunk(chunk: str) -> str | None:
        try:
            return chunk.encode("ascii").decode("utf-7")
        except UnicodeDecodeError:
            pass

        body = chunk[1:-1]
        padded = body + ("=" * ((4 - len(body) % 4) % 4))

        try:
            raw = base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            return None

        if not raw:
            return None

        if len(raw) % 2 == 1:
            raw = raw[:-1]

        if not raw:
            return None

        try:
            return raw.decode("utf-16-be")
        except UnicodeDecodeError:
            return None

    def replacer(match: re.Match[str]) -> str:
        token = match.group(1)
        parts = re.findall(r"\+[A-Za-z0-9/]+-", token)
        decoded_parts: list[str] = []

        for part in parts:
            decoded_part = decode_chunk(part)
            if decoded_part:
                decoded_parts.append(decoded_part)

        if not decoded_parts:
            return token

        decoded = "".join(decoded_parts)

        if not _looks_safe_decoded_text(decoded):
            return token

        if not (contains_suspicious_keyword(decoded) or contains_suspicious_phrase(decoded)):
            return token

        findings.append(
            DecodeFinding(
                kind="utf7",
                original=token,
                decoded=decoded,
                confidence=0.0,
            )
        )

        return token

    return UTF7_SEQUENCE_PATTERN.sub(replacer, text), findings


def _decode_base64_candidate(token: str) -> str | None:
    padded = token + ("=" * ((4 - len(token) % 4) % 4))

    try:
        raw = base64.b64decode(padded, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None

    return decoded if _looks_safe_decoded_text(decoded) else None


def decode_segmented_base64(text: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def replacer(match: re.Match[str]) -> str:
        token = match.group(1)
        segments = re.split(r"[._\-\s]+", token)

        if len(segments) < 2 or len(segments) > 3:
            return token

        if any(len(segment) < 8 for segment in segments):
            return token

        joined = re.sub(r"[._\-\s]+", "", token)
        decoded = _decode_base64_candidate(joined)

        if not decoded:
            return token

        findings.append(
            DecodeFinding(
                kind="base64",
                original=token,
                decoded=decoded,
                confidence=0.0,
            )
        )

        return token

    text = SEGMENTED_BASE64_PATTERN.sub(replacer, text)
    text = SPACE_SEGMENTED_BASE64_PATTERN.sub(replacer, text)

    return text, findings


def _is_standalone_token(text: str, start: int, end: int) -> bool:
    before_ok = start == 0 or text[start - 1].isspace()
    after_ok = end == len(text) or text[end].isspace()
    return before_ok and after_ok


def decode_base64_tokens(text: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def replacer(match: re.Match[str]) -> str:
        token = match.group(1)
        standalone = _is_standalone_token(text, match.start(1), match.end(1))
        decoded = _decode_base64_candidate(token)

        if not decoded:
            return token

        if decoded != decoded.strip() and not standalone:
            return token

        if len(token) < 12:
            if not standalone:
                return token

            if not contains_suspicious_keyword(decoded):
                return token

        findings.append(
            DecodeFinding(
                kind="base64",
                original=token,
                decoded=decoded,
                confidence=0.0,
            )
        )

        return token

    return BASE64_TOKEN_PATTERN.sub(replacer, text), findings


def decode_upper_unicode_escapes(text: str) -> tuple[str, list[DecodeFinding]]:
    updated, findings = decode_unicode_like(
        text,
        UPPER_UNICODE_ESCAPE_PATTERN,
        "unicode_escape",
    )
    updated, more = decode_unicode_like(
        updated,
        DOUBLE_UPPER_UNICODE_ESCAPE_PATTERN,
        "double_unicode_escape",
    )
    findings.extend(more)

    return updated, findings


def decode_hex_tokens(text: str) -> tuple[str, list[DecodeFinding]]:
    findings: list[DecodeFinding] = []

    def replacer(match: re.Match[str]) -> str:
        token = match.group(1)

        if len(token) % 2 != 0:
            return token

        try:
            decoded = bytes.fromhex(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return token

        if not _looks_safe_decoded_text(decoded):
            return token

        findings.append(
            DecodeFinding(
                kind="hex",
                original=token,
                decoded=decoded,
                confidence=0.0,
            )
        )

        return decoded

    return HEX_TOKEN_PATTERN.sub(replacer, text), findings
