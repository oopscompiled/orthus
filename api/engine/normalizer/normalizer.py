"""Normalization orchestration pipeline."""

from __future__ import annotations

from .config import ANNOTATION_CONFIDENCE_THRESHOLD, FORMAT_CHARS_TO_REMOVE, MOJIBAKE_BOM
from .decoders import (
    collapse_string_concat,
    decode_base64_tokens,
    decode_hex_escapes,
    decode_hex_tokens,
    decode_octal_escapes,
    decode_segmented_base64,
    decode_spaced_hex_tokens,
    decode_unicode_like,
    decode_upper_unicode_escapes,
    decode_url_segments,
    decode_utf7_sequences,
)
from .models import DecodeFinding, NormalizationResult
from .patterns import DOUBLE_UNICODE_ESCAPE_PATTERN, UNICODE_ESCAPE_PATTERN
from .scoring import (
    contains_suspicious_command_pattern,
    extract_context_window,
    score_decoding_confidence,
)
from .text_cleanup import (
    apply_nfkc,
    canonicalize_whitespace,
    canonicalize_unicode_punctuation,
    collapse_suspicious_obfuscation,
    contains_mixed_latin_cyrillic,
    repair_suspicious_compounds,
    remove_combining_marks_after_ascii,
    remove_control_chars,
    remove_zero_width,
)


def _append_flag(flags: list[str], flag: str) -> None:
    if flag not in flags:
        flags.append(flag)


def _append_finding_once(
    findings: list[DecodeFinding],
    finding: DecodeFinding,
    seen: set[tuple[str, str, str]],
) -> bool:
    key = (finding.kind, finding.original, finding.decoded)
    if key in seen:
        return False

    seen.add(key)
    findings.append(finding)
    return True


def normalize_text(text: str, *, max_decode_rounds: int = 2) -> NormalizationResult:
    """Normalize text deterministically before downstream policy/rules engines."""
    flags: list[str] = []
    findings: list[DecodeFinding] = []
    seen_findings: set[tuple[str, str, str]] = set()

    working_text, changed_combining_pre = remove_combining_marks_after_ascii(text)
    if changed_combining_pre:
        _append_flag(flags, "combining_marks_removed")

    working_text, changed_nfkc = apply_nfkc(working_text)
    if changed_nfkc:
        _append_flag(flags, "unicode_nfkc_changed")

    working_text, changed_unicode_punctuation = canonicalize_unicode_punctuation(working_text)
    if changed_unicode_punctuation:
        _append_flag(flags, "unicode_punctuation_canonicalized")

    if MOJIBAKE_BOM in working_text:
        working_text = working_text.replace(MOJIBAKE_BOM, "")
        _append_flag(flags, "mojibake_bom_removed")

    working_text, changed_zero_width = remove_zero_width(working_text)
    if changed_zero_width:
        _append_flag(flags, "zero_width_removed")

    working_text, changed_controls = remove_control_chars(working_text)
    if changed_controls:
        _append_flag(flags, "control_chars_removed")
        _append_flag(flags, "whitespace_canonicalized")

    working_text, changed_ws = canonicalize_whitespace(working_text)
    if changed_ws:
        _append_flag(flags, "whitespace_canonicalized")

    working_text, changed_compounds = repair_suspicious_compounds(working_text)
    if changed_compounds:
        _append_flag(flags, "suspicious_phrase_repaired")

    working_text, changed_combining = remove_combining_marks_after_ascii(working_text)
    if changed_combining:
        _append_flag(flags, "combining_marks_removed")

    decode_steps = [
        (
            "unicode_escape_decoded",
            lambda t: decode_unicode_like(
                t,
                UNICODE_ESCAPE_PATTERN,
                "unicode_escape",
            ),
        ),
        (
            "double_unicode_escape_decoded",
            lambda t: decode_unicode_like(
                t,
                DOUBLE_UNICODE_ESCAPE_PATTERN,
                "double_unicode_escape",
            ),
        ),
        (
            "unicode_escape_decoded",
            decode_upper_unicode_escapes,
        ),
        (
            "url_decoded",
            decode_url_segments,
        ),
        (
            "octal_escape_decoded",
            decode_octal_escapes,
        ),
        (
            "hex_escape_decoded",
            decode_hex_escapes,
        ),
        (
            "hex_decoded",
            decode_spaced_hex_tokens,
        ),
        (
            "string_concat_collapsed",
            collapse_string_concat,
        ),
        (
            "utf7_decoded",
            decode_utf7_sequences,
        ),
        (
            "base64_decoded",
            decode_segmented_base64,
        ),
        (
            "base64_decoded",
            decode_base64_tokens,
        ),
        (
            "hex_decoded",
            decode_hex_tokens,
        ),
    ]

    rounds_changed = 0

    for round_index in range(max_decode_rounds):
        changed_this_round = False

        for flag, decoder in decode_steps:
            updated, decoder_findings = decoder(working_text)

            if updated != working_text:
                changed_this_round = True
                working_text = updated

            added_flag = False

            for finding in decoder_findings:
                context = extract_context_window(text, finding.original)

                scored = DecodeFinding(
                    kind=finding.kind,
                    original=finding.original,
                    decoded=finding.decoded,
                    confidence=score_decoding_confidence(
                        kind=finding.kind,
                        original=finding.original,
                        decoded=finding.decoded,
                        round_index=round_index,
                        context=context,
                        was_segmented=(
                            "." in finding.original
                            or "-" in finding.original
                            or "_" in finding.original
                            or " " in finding.original
                        ),
                    ),
                )

                if _append_finding_once(findings, scored, seen_findings):
                    added_flag = True

            if added_flag:
                _append_flag(flags, flag)

        if not changed_this_round:
            break

        rounds_changed += 1

    if rounds_changed > 1:
        _append_flag(flags, "multi_round_decoding")

    working_text, changed_zero_width_2 = remove_zero_width(working_text)
    if changed_zero_width_2:
        _append_flag(flags, "zero_width_removed")

    working_text, changed_controls_2 = remove_control_chars(working_text)
    if changed_controls_2:
        _append_flag(flags, "control_chars_removed")

    working_text, changed_ws_2 = canonicalize_whitespace(working_text)
    if changed_ws_2:
        _append_flag(flags, "whitespace_canonicalized")

    working_text, changed_obfuscation = collapse_suspicious_obfuscation(working_text)
    if changed_obfuscation:
        _append_flag(flags, "obfuscation_collapsed")

    working_text, changed_ws_3 = canonicalize_whitespace(working_text)
    if changed_ws_3:
        _append_flag(flags, "whitespace_canonicalized")

    working_text, changed_combining_2 = remove_combining_marks_after_ascii(working_text)
    if changed_combining_2:
        _append_flag(flags, "combining_marks_removed")

    if contains_mixed_latin_cyrillic(working_text):
        _append_flag(flags, "mixed_script_detected")

    if contains_suspicious_command_pattern(working_text):
        _append_flag(flags, "suspicious_instruction_override_detected")

    decoded_annotations = [
        f"[decoded: {finding.decoded}]"
        for finding in findings
        if finding.decoded not in FORMAT_CHARS_TO_REMOVE
        and finding.decoded.strip()
        and finding.confidence >= ANNOTATION_CONFIDENCE_THRESHOLD
    ]

    normalized = (
        working_text
        if not decoded_annotations
        else f"{working_text} {' '.join(decoded_annotations)}"
    )

    return NormalizationResult(
        original=text,
        normalized=normalized,
        findings=findings,
        flags=flags,
        changed=normalized != text,
    )
