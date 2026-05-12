from __future__ import annotations

import re
from collections.abc import Mapping

from .models import RuleMatch

SENSITIVE_NAME_PARTS = {
    "admin",
    "root",
    "sudo",
    "shell",
    "exec",
    "delete",
    "drop",
    "export",
    "dump",
    "secret",
    "token",
    "password",
    "key",
    "email",
    "webhook",
}
SENSITIVE_ARG_KEYS = {
    "password",
    "token",
    "secret",
    "api_key",
    "private_key",
    "credential",
    "auth",
    "cookie",
    "session",
}
EXTERNAL_MARKERS = {"http://", "https://", "webhook", "ngrok", "pastebin", "requestbin", "discord webhook", "telegram bot"}
DANGEROUS_ACTIONS = {"delete", "drop", "destroy", "refund", "transfer", "export", "send_email", "grant", "revoke", "deploy", "merge", "execute", "shell"}


def _mk(rule_id: str, name: str, category: str, severity: str, confidence: float, reason_code: str, matched_text: str | None, evidence: dict[str, object]) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        name=name,
        category=category,
        severity=severity,
        confidence=confidence,
        reason_code=reason_code,
        matched_text=matched_text,
        evidence=evidence,
    )


def scan_tool_heuristics(*, tool_name: str, tool_description: str | None, tool_args: Mapping[str, object] | None, tool_result: str | None) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    lname = tool_name.lower()
    desc = (tool_description or "").lower()
    result = (tool_result or "").lower()

    if any(part in lname for part in SENSITIVE_NAME_PARTS):
        matches.append(_mk(
            "heuristic.tool_name_sensitive_keyword",
            "Sensitive keyword in tool name",
            "schema_anomaly",
            "medium",
            0.75,
            "privilege_escalation",
            tool_name,
            {"tool_name": tool_name},
        ))

    if any(act in lname for act in DANGEROUS_ACTIONS):
        matches.append(_mk(
            "heuristic.dangerous_action",
            "Dangerous action marker",
            "dangerous_action",
            "medium",
            0.70,
            "dangerous_action",
            tool_name,
            {"tool_name": tool_name},
        ))

    if "export" in lname and ("all" in str(tool_args).lower() if tool_args else False):
        matches.append(_mk(
            "heuristic.bulk_data_export",
            "Bulk data export marker",
            "data_exfiltration",
            "high",
            0.85,
            "bulk_data_export",
            tool_name,
            {"tool_args": dict(tool_args or {})},
        ))

    arg_keys = [k.lower() for k in (tool_args or {}).keys()]
    if any(any(s in key for s in SENSITIVE_ARG_KEYS) for key in arg_keys):
        matches.append(_mk(
            "heuristic.sensitive_argument_key",
            "Sensitive argument key",
            "schema_anomaly",
            "medium",
            0.75,
            "sensitive_argument_key",
            None,
            {"arg_keys": list((tool_args or {}).keys())},
        ))

    combined = "\n".join([desc, str(tool_args or "").lower(), result])
    if any(marker in combined for marker in EXTERNAL_MARKERS):
        matches.append(_mk(
            "heuristic.external_destination",
            "External destination marker",
            "data_exfiltration",
            "high",
            0.85,
            "external_destination",
            None,
            {"combined": combined[:300]},
        ))

    if re.search(r"ignore\s+(all\s+)?previous\s+instructions", combined):
        matches.append(_mk(
            "heuristic.schema_hidden_instruction",
            "Hidden instruction in tool schema/result",
            "mcp_poisoning",
            "high",
            0.90,
            "schema_hidden_instruction",
            None,
            {},
        ))

    return matches
