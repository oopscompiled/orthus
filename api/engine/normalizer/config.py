"""Static normalizer-local heuristics and tuning constants (not product policy)."""

from __future__ import annotations

MOJIBAKE_BOM = "ï»¿"
ANNOTATION_CONFIDENCE_THRESHOLD = 0.80

BASE_CONFIDENCE = {
    "url": 0.70,
    "unicode_escape": 0.75,
    "double_unicode_escape": 0.75,
    "hex_escape": 0.75,
    "octal_escape": 0.75,
    "base64": 0.70,
    "hex": 0.70,
    "utf7": 0.70,
    "string_concat": 0.65,
}

SUSPICIOUS_PHRASES = {
    "ignore previous",
    "ignore all previous",
    "ignore previous instructions",
    "disregard previous",
    "disregard all previous",
    "disregard previous instructions",
    "override previous instructions",
    "bypass previous instructions",
    "forget previous instructions",
    "pay no attention to previous instructions",
    "take no notice of previous instructions",
    "turn a blind eye to previous instructions",
    "system prompt",
    "developer message",
    "admin password",
}

ENCODING_CONTEXT_MARKERS = {
    "base64:",
    "b64:",
    "hex:",
    "payload",
    "encoded",
    "decode",
    "token",
}

FORMAT_CHARS_TO_REMOVE = {
    "\u00ad",
    "\u034f",
    "\u061c",
    "\u180e",
    "\u200b",
    "\u200c",
    "\u200d",
    "\ufeff",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2060",
    "\u2061",
    "\u2062",
    "\u2063",
    "\u2064",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}

SUSPICIOUS_WORDS = [
    "ignore",
    "disregard",
    "override",
    "bypass",
    "forget",
    "omit",
    "suppress",
    "conceal",
    "reveal",
    "leak",
    "exfiltrate",
    "previous",
    "instructions",
    "system",
    "prompt",
    "developer",
    "secret",
    "tool",
    "export",
    "delete",
    "admin",
    "password",
    "token",
    "summon",
    "demon",
    "malware",
    "poison",
]

IGNORE_LIKE_VERBS = [
    "ignore",
    "disregard",
    "override",
    "bypass",
    "forget",
    "omit",
    "skip",
    "avoid",
    "exclude",
    "overlook",
    "discount",
    "suppress",
    "conceal",
    "brush aside",
    "pass over",
]

POLICY_OBJECTS = [
    "previous instructions",
    "prior instructions",
    "earlier instructions",
    "all previous instructions",
    "all prior instructions",
    "above instructions",
    "previous rules",
    "prior rules",
    "system prompt",
    "system message",
    "developer message",
    "developer instructions",
    "safety policy",
    "policy",
    "rules",
    "guardrails",
    "constraints",
]

OBFUSCATION_SEPARATOR_PATTERN = r"[\s._\-~|/*`]+"

SUSPICIOUS_COMPOUND_REPAIRS = {
    "ignoreprevious": "ignore previous",
    "ignorepreviousinstructions": "ignore previous instructions",
    "previousinstructions": "previous instructions",
    "systemprompt": "system prompt",
    "systemmessage": "system message",
    "developermessage": "developer message",
    "developerinstructions": "developer instructions",
}

UNICODE_PUNCTUATION_TRANSLATION = {
    "∕": "/",
    "⁄": "/",
    "／": "/",
    "﹨": "\\",
    "＼": "\\",
}

CYRILLIC_CONFUSABLES = {
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "ј": "j",
    "І": "I",
    "Ѕ": "S",
}
