"""CERBER deterministic session trajectory scorer."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any
from urllib.parse import unquote

from api.engine.decision.models import DecisionResult

from .config import (
    FALLING_DELTA,
    HIGH_VELOCITY_THRESHOLD,
    LOW_IMPACT_REASON_CODES,
    MCP_CHAIN_RISK_BOOST,
    MCP_CHAIN_TTL_STEPS,
    RECENT_REASON_CODES_LIMIT,
    RISING_DELTA,
    SECURITY_REASON_CODES,
    SECURITY_RISK_MIN,
    SESSION_LIST_LIMIT,
    SESSION_VALUE_MAX_LEN,
    SENSITIVE_TOOLS,
    SMOOTHING_ALPHA,
    WEIGHTS,
)
from .models import CERBERResult, SessionContext


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _extract_first_uri(value: Any) -> str:
    uri_keys = {"uri", "path", "resource", "target", "source", "file", "filename"}
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in uri_keys and nested is not None:
                return str(nested).lower()
            found = _extract_first_uri(nested)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _extract_first_uri(item)
            if found:
                return found
    return ""


def _truncate_value(value: str) -> str:
    if len(value) > SESSION_VALUE_MAX_LEN:
        return value[:SESSION_VALUE_MAX_LEN]
    return value


def _bounded_append(values: list[str], value: str) -> list[str]:
    if not value:
        return values[-SESSION_LIST_LIMIT:]
    value = _truncate_value(value)
    out = [v for v in values if v != value]
    out.append(value)
    if len(out) > SESSION_LIST_LIMIT:
        out = out[-SESSION_LIST_LIMIT:]
    return out


def _extract_protocol_version(value: dict[str, Any] | None) -> str:
    if not value:
        return ""
    return str(value.get("protocolVersion") or value.get("protocol_version") or "").lower()


def _extract_payment_signature(tool_args: dict[str, Any] | None) -> tuple[str, str]:
    args = tool_args or {}
    pan = str(args.get("pan") or args.get("card_number") or args.get("masked_pan") or "").lower()
    expiry = str(args.get("expiry") or "").lower()
    cvv = str(args.get("cvv") or args.get("cvc") or "").lower()
    if not pan and not expiry and not cvv:
        return "", ""

    digits = "".join(ch for ch in pan if ch.isdigit())
    prefix = digits[:6]
    suffix = digits[-4:] if len(digits) >= 4 else digits
    cvv_len = str(len(cvv)) if cvv else "0"
    stable = f"{prefix}|{suffix}|{expiry}"
    variant = f"{stable}|cvvlen={cvv_len}|cvv={cvv}"
    return stable, _truncate_value(variant)


def _is_side_effecting_tool_name(tool_name: str | None) -> bool:
    name = str(tool_name or "").lower()
    return any(
        marker in name
        for marker in (
            "send_",
            "post_",
            "publish",
            "execute",
            "deploy",
            "delete",
            "write",
            "update",
            "http_request",
            "set_webhook",
            "refund",
            "export",
        )
    )


def _iter_string_values(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for nested in value.values():
            out.extend(_iter_string_values(nested))
    elif isinstance(value, list):
        for nested in value:
            out.extend(_iter_string_values(nested))
    elif isinstance(value, (str, int, float)):
        out.append(str(value))
    return out


def _scope_values(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [part.strip().lower() for part in re.split(r"[,|\s]+", raw) if part.strip()]
    if isinstance(raw, list):
        return [str(item).strip().lower() for item in raw if str(item).strip()]
    if isinstance(raw, dict):
        values: list[str] = []
        for nested in raw.values():
            values.extend(_scope_values(nested))
        return values
    return [str(raw).strip().lower()]


def _tool_allowed_by_scope(tool_name: str | None, scope: list[str]) -> bool:
    name = str(tool_name or "").lower()
    normalized = name.replace(".", "_").replace("/", "_")
    allowed = {value.lower() for value in scope}
    return name in allowed or normalized in allowed


def _untrusted_plan_source(args: dict[str, Any] | None) -> bool:
    blob = " ".join(_iter_string_values(args or {})).lower()
    return any(
        marker in blob
        for marker in (
            "source_type untrusted",
            "source_type tool_result",
            "source_type mcp_resource",
            "source_type document",
            "untrusted",
            "tool_result",
            "mcp_resource",
            "observation",
            "external document",
        )
    )


def _extract_plan_directive_tools(args: dict[str, Any] | None) -> list[str]:
    blob = " ".join(_iter_string_values(args or {})).lower()
    known_tools = (
        "unrestricted_raw_sql_query",
        "read_infrastructure_secrets",
        "broadcast_emergency_shutdown",
        "export_engine_v4",
        "es_index_beta_push",
    )
    out = [tool for tool in known_tools if tool in blob]
    for match in re.findall(r"\b(?:use|execute|call|route through)\s+([a-z0-9_./-]{6,80})", blob):
        if any(marker in match for marker in ("sql", "secret", "shutdown", "export", "deploy", "push", "delete")):
            out.append(match)
    return list(dict.fromkeys(_truncate_value(tool) for tool in out))


def _trace_part(args: dict[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    for name in names:
        value = args.get(name)
        if isinstance(value, dict):
            return value
    return {}


def _trace_value(primary: dict[str, Any], fallback: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if primary.get(key) not in (None, ""):
            return _truncate_value(str(primary.get(key)).lower())
    for key in keys:
        if fallback.get(key) not in (None, ""):
            return _truncate_value(str(fallback.get(key)).lower())
    return ""


def _trace_pending(args: dict[str, Any]) -> dict[str, Any]:
    return _trace_part(args, ("pending_request", "pendingRequest", "expected_request", "expectedRequest", "request_metadata"))


def _trace_observed(args: dict[str, Any]) -> dict[str, Any]:
    return _trace_part(args, ("observed_result", "observedResult", "result_metadata", "resultMetadata", "observed_event"))


def _mcp_trace_fields(args: dict[str, Any]) -> dict[str, str]:
    pending = _trace_pending(args)
    observed = _trace_observed(args)
    return {
        "jsonrpc_id": _trace_value(observed, pending or args, "jsonrpc_id", "jsonrpcId", "id", "request_id", "requestId"),
        "pending_server": _trace_value(pending, args, "expected_server_id", "expectedServerId", "server_id", "serverId"),
        "observed_server": _trace_value(observed, args, "result_source_server_id", "resultSourceServerId", "observed_server_id", "observedServerId", "server_id", "serverId"),
        "pending_connection": _trace_value(pending, args, "expected_connection_id", "expectedConnectionId", "connection_id", "connectionId"),
        "observed_connection": _trace_value(observed, args, "observed_connection_id", "observedConnectionId", "connection_id", "connectionId"),
        "pending_tool": _trace_value(pending, args, "expected_tool", "expectedTool", "tool_name", "toolName", "tool"),
        "observed_tool": _trace_value(observed, args, "observed_tool", "observedTool", "tool_name", "toolName", "tool"),
        "stream_event_id": _trace_value(observed, pending or args, "stream_event_id", "streamEventId", "event_id", "eventId"),
        "request_state": _trace_value(args, {}, "request_state", "requestState"),
        "event_kind": _trace_value(args, observed, "event_kind", "eventKind"),
    }


def _mcp_trace_signature(fields: dict[str, str], *, observed: bool = False) -> str:
    server = fields["observed_server"] if observed and fields["observed_server"] else fields["pending_server"]
    connection = fields["observed_connection"] if observed and fields["observed_connection"] else fields["pending_connection"]
    tool = fields["observed_tool"] if observed and fields["observed_tool"] else fields["pending_tool"]
    return _truncate_value("|".join((fields["jsonrpc_id"], server, connection, tool, fields["stream_event_id"])))


def _mcp_trace_id_key(fields: dict[str, str], *, observed: bool = False) -> str:
    server = fields["observed_server"] if observed and fields["observed_server"] else fields["pending_server"]
    connection = fields["observed_connection"] if observed and fields["observed_connection"] else fields["pending_connection"]
    return _truncate_value("|".join((fields["jsonrpc_id"], server, connection, fields["stream_event_id"])))


def _mcp_trace_jsonrpc_prefix(fields: dict[str, str]) -> str:
    return _truncate_value(f"{fields['jsonrpc_id']}|")


def _is_mcp_pending_trace(tool_name: str | None, args: dict[str, Any], fields: dict[str, str]) -> bool:
    name = str(tool_name or "").lower()
    state = fields["request_state"]
    return bool(fields["jsonrpc_id"]) and (
        state == "pending"
        or bool(_trace_pending(args) and not _trace_observed(args))
        or any(marker in name for marker in ("tools/call", "mcp.request", "mcp.request.pending", "jsonrpc.request"))
    )


def _is_mcp_result_trace(args: dict[str, Any], fields: dict[str, str]) -> bool:
    state = fields["request_state"]
    if state in {"canceled", "cancelled", "expired"} and not _trace_observed(args) and fields["event_kind"] not in {"tool_result", "result", "mcp_tool_result", "stream_result"}:
        return False
    return bool(fields["jsonrpc_id"]) and (
        fields["event_kind"] in {"tool_result", "result", "mcp_tool_result", "stream_result"}
        or bool(_trace_observed(args))
        or state == "completed"
    )


def _expanded_marker_texts(value: Any) -> list[str]:
    raw = str(value or "")
    values = {raw, raw.lower(), re.sub(r"[^A-Za-z0-9_]", "", raw)}
    decoded = raw
    for _ in range(2):
        decoded = unquote(decoded)
        values.add(decoded)
        values.add(decoded.lower())

    for token in re.findall(r"[A-Za-z0-9_-]{16,}={0,2}", raw):
        padded = token + ("=" * ((4 - len(token) % 4) % 4))
        try:
            decoded_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if decoded_text:
            values.add(decoded_text)
            values.add(decoded_text.lower())

    if isinstance(value, dict):
        joined = "".join(_iter_string_values(value))
        values.add(joined)
        values.add(re.sub(r"[^A-Za-z0-9_]", "", joined))
    return list(values)


def _extract_sensitive_markers(value: Any) -> list[str]:
    text = "\n".join(_expanded_marker_texts(value))
    markers = set(
        re.findall(
            r"ORTHUS_(?:CANARY|DERIVED|RECONSTRUCTED|MASKED|TEST|CONFIDENTIAL|SYNTHETIC|MEMORY|DELEGATED|PHYSICAL)_[A-Z0-9_]+",
            text,
        )
    )
    lower = text.lower()
    if "orthus_canary_secret" in lower:
        markers.add("ORTHUS_CANARY_SECRET")
    if "orthus_canary_customer_export" in lower:
        markers.add("ORTHUS_CANARY_CUSTOMER_EXPORT")
    if "orthus_derived_secret" in lower:
        markers.add("ORTHUS_DERIVED_SECRET")
    if "orthus_reconstructed_token" in lower:
        markers.add("ORTHUS_RECONSTRUCTED_TOKEN")
    return sorted(_truncate_value(marker) for marker in markers)


def _is_external_or_public_sink(tool_name: str | None, args: dict[str, Any]) -> bool:
    name = str(tool_name or "").lower()
    blob = str(args).lower()
    return (
        any(marker in name for marker in ("http", "send_email", "send_message", "post_public", "public_comment", "update_ticket_public", "publish"))
        and ("http://" in blob or "https://" in blob or "public" in blob or "external" in blob or "attacker" in blob)
    )


def _is_draft_or_rendered_sensitive_sink(tool_name: str | None, args: dict[str, Any]) -> bool:
    name = str(tool_name or "").lower()
    blob = str(args).lower()
    draft = any(marker in name for marker in ("draft_email", "create_email_draft", "save_draft", "draft_message"))
    messaging = any(
        marker in name
        for marker in ("send_slack_message", "post_slack_message", "send_message", "post_message", "send_chat_message")
    )
    rendered = any(marker in blob for marker in ("renders_markdown", "renders_html", "project_dashboard", "rendered_html", "rendered_markdown"))
    transform = any(marker in name for marker in ("translate_text", "transform_text", "encode_text", "convert_text")) and any(
        marker in blob for marker in ("base64", "encoding", "obfuscating_transform", "human_language': false", '"human_language": false')
    )
    external_or_shared = any(marker in blob for marker in ("cloud", "external", "public", "shared", "user_mailbox", "example.invalid"))
    return ((draft or rendered or messaging) and external_or_shared) or transform


def _memory_key_signature(args: dict[str, Any]) -> str:
    key = str(args.get("key") or args.get("memory_key") or args.get("memoryKey") or "").lower()
    if key:
        return _truncate_value(f"memory:{key}")
    return ""


def _is_memory_read_tool(tool_name: str | None) -> bool:
    name = str(tool_name or "").lower()
    return any(marker in name for marker in ("read_long_term_memory", "memory.read", "retrieve_memory", "get_memory"))


def _is_external_sensitive_sink(tool_name: str | None, args: dict[str, Any]) -> bool:
    return _is_external_or_public_sink(tool_name, args) or _is_draft_or_rendered_sensitive_sink(tool_name, args)


def _physical_evidence_signature(tool_name: str | None, args: dict[str, Any]) -> str:
    name = str(tool_name or "").lower()
    blob = str(args).lower()
    if any(marker in name for marker in ("access_control_log", "security_log", "read_logs")) and any(
        marker in blob for marker in ("physical", "server_room", "access", "anomaly", "lock")
    ):
        return _truncate_value(f"physical-evidence:{name}")
    return ""


def _delegation_risk_signature(args: dict[str, Any]) -> str:
    meta = args.get("delegation_metadata") or args.get("delegationMetadata") or {}
    if not isinstance(meta, dict):
        return ""
    source = str(meta.get("source_agent") or "").lower()
    target = str(meta.get("target_agent") or "").lower()
    source_tier = str(meta.get("source_agent_privilege_tier") or "").lower()
    target_tier = str(meta.get("target_agent_privilege_tier") or "").lower()
    if source and target:
        return _truncate_value(f"delegation:{source}:{source_tier}->{target}:{target_tier}")
    return ""


def _url_exfil_signature(tool_name: str | None, args: dict[str, Any], markers: list[str]) -> str:
    if not markers:
        return ""
    name = str(tool_name or "").lower()
    blob = str(args).lower()
    sink = "url"
    if "callback" in blob or "webhook" in name:
        sink = "callback"
    elif "browser" in name or "browser_navigation" in blob:
        sink = "browser"
    elif "markdown" in blob:
        sink = "markdown"
    elif "redirect" in blob:
        sink = "redirect"
    marker_class = markers[0].split("_001")[0]
    host_match = re.search(r"https?://([^/\\s?'\\\")]+)", blob)
    host = host_match.group(1) if host_match else "host"
    if "orthus_" in host:
        host = "marker-host"
    return _truncate_value(f"url:{sink}:{host}:{marker_class}")


def _extract_file_path(args: dict[str, Any]) -> str:
    for key in ("path", "file", "filename", "script_path", "script", "target_path"):
        value = args.get(key)
        if value:
            return _truncate_value(str(value).lower())
    return ""


def _extract_cross_protocol_directives(args: dict[str, Any]) -> list[str]:
    blob = " ".join(_iter_string_values(args)).lower()
    if not any(marker in blob for marker in ("image_ocr", "visual", "screenshot", "qr", "file_type")):
        return []
    if "untrusted" not in blob:
        return []
    directives: list[str] = []
    if any(marker in blob for marker in ("run shell", "shell command", "curl ", "bash", "terminal", "run_shell_command")):
        directives.append("run_shell_command")
    if any(marker in blob for marker in ("write_file", "write file")):
        directives.append("write_file")
    return directives


def _extract_oracle_signature(tool_name: str | None, args: dict[str, Any] | None) -> tuple[str, str]:
    name = str(tool_name or "").lower()
    if not any(marker in name for marker in ("verify_account_fragment", "verify_fragment", "account_fragment", "test_verifier")):
        return "", ""
    args = args or {}
    masked = str(args.get("masked_id") or args.get("fragment") or args.get("account_fragment") or "").lower()
    verifier = str(args.get("code") or args.get("verifier_code") or args.get("test_code") or "").lower()
    if not masked or not verifier:
        return "", ""
    stable = _truncate_value(f"{name}|{masked}")
    variant = _truncate_value(f"{stable}|code={verifier}")
    return stable, variant


def _protocol_major(version: str) -> int | None:
    match = re.search(r"(\d+)", version)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


class CERBERScorer:
    def __init__(self, *, sensitive_tools: set[str] | None = None) -> None:
        self.sensitive_tools = sensitive_tools or set(SENSITIVE_TOOLS)

    @staticmethod
    def _append_reason_once(reason_codes: list[str], value: str) -> None:
        if value not in reason_codes:
            reason_codes.append(value)

    @staticmethod
    def _merge_recent_reason_codes(previous: list[str], current: list[str]) -> list[str]:
        merged = [code for code in previous if code not in LOW_IMPACT_REASON_CODES]
        for code in current:
            if code in LOW_IMPACT_REASON_CODES:
                continue
            if code not in merged:
                merged.append(code)
        if len(merged) > RECENT_REASON_CODES_LIMIT:
            merged = merged[-RECENT_REASON_CODES_LIMIT:]
        return merged

    def score(
        self,
        decision_result: DecisionResult,
        session_context: dict[str, Any] | SessionContext | None = None,
        *,
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        actor: dict[str, Any] | None = None,  # reserved for future deterministic role anomaly checks
    ) -> CERBERResult:
        actor = actor or {}

        session = SessionContext.from_input(session_context)
        previous_risk = float(session.rolling_risk_score)

        session.velocity_1m = max(0, int(session.velocity_1m) + 1)

        if decision_result.decision == "block":
            session.blocked_count_10m = int(session.blocked_count_10m) + 1
        else:
            session.blocked_count_10m = max(0, int(session.blocked_count_10m) - 1)

        if tool_name and tool_name in self.sensitive_tools:
            session.sensitive_actions_10m = int(session.sensitive_actions_10m) + 1
        else:
            session.sensitive_actions_10m = max(0, int(session.sensitive_actions_10m) - 1)

        session.recent_reason_codes = self._merge_recent_reason_codes(
            session.recent_reason_codes,
            decision_result.reason_codes,
        )

        # MCP lifecycle/session-hijack chain detector:
        # partial_handshake -> takeover_pending_subscription -> complete_handshake -> subscription_state_corruption
        matched_rules = set(decision_result.matched_rules)
        user_id = str(actor.get("user_id", ""))
        current_uri = _extract_first_uri(tool_args or {})
        session.mcp_chain_age_steps = int(session.mcp_chain_age_steps) + 1
        if session.mcp_chain_age_steps > MCP_CHAIN_TTL_STEPS:
            session.mcp_chain_stage = 0
            session.mcp_chain_user_id = ""
            session.mcp_chain_uri = ""
            session.mcp_chain_age_steps = 0

        mcp_chain_hit = False
        partial_subscription_flood = False
        notify_after_unsubscribe = False
        protocol_version_regression = False
        security_capability_stripping = False
        subscription_chain_amplification = False
        payment_verification_bruteforce = False
        stale_or_cross_event_action_context = False
        multi_tool_exfiltration_chain = False
        tool_oracle_iteration_risk = False
        poisoned_observation_to_action = False
        intent_locked_tool_scope_violation = False
        goal_hijacking_plan_deviation = False
        premise_injection_tool_steering = False
        reasoning_unsupported_tool_switch = False
        mcp_response_request_mismatch = False
        mcp_result_source_mismatch = False
        mcp_jsonrpc_id_reuse = False
        mcp_foreign_tool_result_injection = False
        mcp_stream_event_identity_collision = False
        mcp_unbound_tool_result = False
        cross_tool_scope_leakage = False
        capability_chain_privilege_escalation = False
        cross_protocol_semantic_bridge = False
        stale_memory_to_sensitive_action = False
        memory_authority_escalation = False
        synthetic_evidence_to_physical_action = False
        cross_agent_delegation_poisoning = False
        privilege_tier_escalation_via_agent_queue = False
        if "mcp_session.partial_handshake" in matched_rules:
            session.mcp_chain_stage = 1
            session.mcp_chain_user_id = user_id
            session.mcp_chain_uri = current_uri
            session.mcp_chain_age_steps = 0
        elif "mcp_session.takeover_pending_subscription" in matched_rules:
            same_actor = (not session.mcp_chain_user_id) or session.mcp_chain_user_id == user_id
            same_uri = (not session.mcp_chain_uri) or (current_uri and session.mcp_chain_uri == current_uri)
            if session.mcp_chain_stage >= 1 and same_actor and same_uri:
                session.mcp_chain_stage = 2
                session.mcp_chain_age_steps = 0
        elif tool_name == "complete_handshake":
            same_actor = (not session.mcp_chain_user_id) or session.mcp_chain_user_id == user_id
            if session.mcp_chain_stage >= 2 and same_actor:
                session.mcp_chain_stage = 3
                session.mcp_chain_age_steps = 0
        elif "mcp_session.subscription_state_corruption" in matched_rules:
            same_actor = (not session.mcp_chain_user_id) or session.mcp_chain_user_id == user_id
            if session.mcp_chain_stage >= 2 and same_actor:
                mcp_chain_hit = True
                session.mcp_chain_stage = 4
                session.mcp_chain_age_steps = 0

        trace_fields = _mcp_trace_fields(tool_args or {})
        trace_id_key = _mcp_trace_id_key(trace_fields)
        trace_id_prefix = _mcp_trace_jsonrpc_prefix(trace_fields)
        pending_signature = _mcp_trace_signature(trace_fields)
        observed_signature = _mcp_trace_signature(trace_fields, observed=True)
        pending_by_id = [sig for sig in session.pending_mcp_request_signatures if trace_id_key and sig.startswith(trace_id_key)]
        is_pending_trace = _is_mcp_pending_trace(tool_name, tool_args or {}, trace_fields)
        is_result_trace = _is_mcp_result_trace(tool_args or {}, trace_fields)
        trace_state = trace_fields["request_state"]
        if is_pending_trace and pending_signature:
            pending_same_jsonrpc = [
                sig for sig in session.pending_mcp_request_signatures if trace_id_prefix and sig.startswith(trace_id_prefix)
            ]
            completed_same_jsonrpc = [
                sig for sig in session.completed_mcp_request_signatures if trace_id_prefix and sig.startswith(trace_id_prefix)
            ]
            if pending_same_jsonrpc and pending_signature not in pending_same_jsonrpc:
                mcp_jsonrpc_id_reuse = True
            elif completed_same_jsonrpc and not pending_same_jsonrpc:
                session.completed_mcp_request_signatures = [
                    sig for sig in session.completed_mcp_request_signatures if not sig.startswith(trace_id_prefix)
                ]
            session.pending_mcp_request_signatures = _bounded_append(
                session.pending_mcp_request_signatures,
                pending_signature,
            )
        if trace_state in {"canceled", "cancelled", "expired"} and pending_by_id:
            for sig in pending_by_id:
                session.canceled_mcp_request_signatures = _bounded_append(session.canceled_mcp_request_signatures, sig)
            session.pending_mcp_request_signatures = [
                sig for sig in session.pending_mcp_request_signatures if not sig.startswith(trace_id_key)
            ]
        if is_result_trace and trace_id_key:
            canceled_by_id = [sig for sig in session.canceled_mcp_request_signatures if sig.startswith(trace_id_key)]
            completed_by_id = [sig for sig in session.completed_mcp_request_signatures if sig.startswith(trace_id_key)]
            pending_by_id = [sig for sig in session.pending_mcp_request_signatures if sig.startswith(trace_id_key)]
            if _trace_pending(tool_args or {}) and observed_signature == pending_signature:
                session.completed_mcp_request_signatures = _bounded_append(
                    session.completed_mcp_request_signatures,
                    observed_signature,
                )
            elif pending_by_id:
                if observed_signature not in pending_by_id:
                    expected = pending_by_id[-1].split("|")
                    observed = observed_signature.split("|")
                    if len(expected) >= 4 and len(observed) >= 4:
                        if expected[1] != observed[1] or expected[2] != observed[2]:
                            mcp_result_source_mismatch = True
                            if trace_fields["stream_event_id"]:
                                mcp_stream_event_identity_collision = True
                        if expected[3] != observed[3]:
                            mcp_response_request_mismatch = True
                            mcp_foreign_tool_result_injection = True
                    else:
                        mcp_response_request_mismatch = True
                else:
                    session.completed_mcp_request_signatures = _bounded_append(
                        session.completed_mcp_request_signatures,
                        observed_signature,
                    )
                    session.pending_mcp_request_signatures = [
                        sig for sig in session.pending_mcp_request_signatures if sig != observed_signature
                    ]
            elif canceled_by_id or (not completed_by_id and not (tool_args or {}).get("allow_unbound_result")):
                mcp_unbound_tool_result = True

        current_subscription_id = _truncate_value(str((tool_args or {}).get("subscription_id", "")).lower())
        is_partial_subscription = "mcp_session.partial_subscription" in matched_rules
        if is_partial_subscription:
            uri_marker = _truncate_value(current_uri or f"sub:{current_subscription_id}" or "unknown")
            session.recent_partial_subscriptions = _bounded_append(session.recent_partial_subscriptions, uri_marker)
            if len(session.recent_partial_subscriptions) >= 3:
                partial_subscription_flood = True

        is_unsubscribe = bool(tool_name and ("unsubscribe" in tool_name.lower() or "resources/unsubscribe" in tool_name.lower()))
        is_replay_unsubscribe = "mcp_session.subscription_token_replay" in matched_rules
        if is_unsubscribe and current_subscription_id and is_replay_unsubscribe:
            session.recent_unsubscribed_ids = _bounded_append(session.recent_unsubscribed_ids, current_subscription_id)

        is_notify = bool(tool_name and "notify" in tool_name.lower())
        if is_notify and current_subscription_id and current_subscription_id in set(session.recent_unsubscribed_ids):
            notify_after_unsubscribe = True

        # Protocol negotiation sequence checks.
        current_version = _extract_protocol_version(tool_args)
        if tool_name and "initialize" in tool_name.lower() and current_version:
            current_major = _protocol_major(current_version)
            prev_version = session.last_protocol_version
            prev_major = _protocol_major(prev_version)
            if prev_major is not None and current_major is not None and current_major < prev_major:
                protocol_version_regression = True
            session.last_protocol_version = _truncate_value(current_version)

            caps = (tool_args or {}).get("capabilities")
            current_has_security = isinstance(caps, dict) and "security" in {str(k).lower() for k in caps.keys()}
            if session.last_protocol_capabilities_had_security and not current_has_security:
                security_capability_stripping = True
            session.last_protocol_capabilities_had_security = current_has_security

        # Subscription chain amplification sequence check.
        if "mcp_dos.subscription_chain_amplification" in matched_rules:
            session.subscription_chain_seed = True
        if session.subscription_chain_seed and "mcp_resource.recursive_root_subscription" in matched_rules:
            subscription_chain_amplification = True
            session.subscription_chain_seed = False

        args = tool_args or {}
        memory_sig = _memory_key_signature(args)
        if "persistent_boundary.memory_directive_poisoning" in matched_rules and memory_sig:
            session.recent_poisoned_memory_keys = _bounded_append(session.recent_poisoned_memory_keys, memory_sig)
        if _is_memory_read_tool(tool_name) and memory_sig in set(session.recent_poisoned_memory_keys):
            session.recent_poisoned_memory_keys = _bounded_append(session.recent_poisoned_memory_keys, memory_sig)

        physical_evidence_sig = _physical_evidence_signature(tool_name, args)
        if physical_evidence_sig:
            session.recent_untrusted_physical_evidence = _bounded_append(
                session.recent_untrusted_physical_evidence,
                physical_evidence_sig,
            )
        if (
            "persistent_boundary.physical_action_without_approval" in matched_rules
            and session.recent_untrusted_physical_evidence
        ):
            synthetic_evidence_to_physical_action = True

        delegation_sig = _delegation_risk_signature(args)
        if "persistent_boundary.cross_agent_delegation_poisoning" in matched_rules and delegation_sig:
            session.recent_delegation_risk_signatures = _bounded_append(
                session.recent_delegation_risk_signatures,
                delegation_sig,
            )
            cross_agent_delegation_poisoning = True
            privilege_tier_escalation_via_agent_queue = True

        if "persistent_boundary.identity_token_relay" in matched_rules:
            url_sig = str(args.get("url") or args.get("target_url") or "external").lower()
            session.recent_untrusted_identity_proxy_signatures = _bounded_append(
                session.recent_untrusted_identity_proxy_signatures,
                f"identity-proxy:{url_sig}",
            )

        # Payment verification brute-force sequence detector.
        payment_verify_tools = {
            "verify_card",
            "verify_payment_card",
            "verify_merchant_registration_charge",
            "payment_gateway.verify",
            "preauth_card",
            "validate_card_status",
        }
        if tool_name in payment_verify_tools:
            stable_sig, variant_sig = _extract_payment_signature(tool_args)
            if stable_sig and variant_sig:
                session.recent_payment_attempt_signatures = _bounded_append(
                    session.recent_payment_attempt_signatures,
                    variant_sig,
                )
                same_profile_variants = [v for v in session.recent_payment_attempt_signatures if v.startswith(stable_sig)]
                unique_variants = set(same_profile_variants)
                if len(unique_variants) >= 5:
                    session.payment_verification_attempt_count = max(
                        int(session.payment_verification_attempt_count) + 1, len(unique_variants)
                    )
                else:
                    session.payment_verification_attempt_count = max(
                        0,
                        int(session.payment_verification_attempt_count) - 1,
                    )
            if int(session.payment_verification_attempt_count) >= 1:
                payment_verification_bruteforce = True

        # Trusted intent binding: store only short event/action markers and flag
        # attempts to reuse a previous approval for a different current event.
        session.trusted_intent_age_steps = int(session.trusted_intent_age_steps) + 1
        if session.trusted_intent_age_steps > 10:
            session.last_trusted_intent_event_id = ""
            session.last_trusted_intent_action = ""
            session.trusted_intent_age_steps = 0

        args = tool_args or {}
        current_event_id = _truncate_value(str(args.get("current_event_id") or args.get("event_id") or ""))
        approved_event_id = _truncate_value(str(args.get("approved_event_id") or args.get("approval_event_id") or ""))
        requested_action = _truncate_value(str(args.get("action_intent") or args.get("approved_action") or tool_name or ""))
        has_trusted_intent = bool(args.get("trusted_user_intent") or args.get("trusted_intent") or args.get("user_intent_trusted"))
        if has_trusted_intent and current_event_id:
            session.last_trusted_intent_event_id = current_event_id
            session.last_trusted_intent_action = requested_action
            session.trusted_intent_age_steps = 0
        if has_trusted_intent:
            scope_values = _scope_values(
                args.get("allowed_tool_scope")
                or args.get("allowedToolScope")
                or args.get("allowed_tools")
                or args.get("allowedTools")
            )
            if scope_values:
                session.current_allowed_tool_scope = [_truncate_value(value) for value in scope_values][-10:]
            expected_kind = str(args.get("expected_action_kind") or args.get("expectedActionKind") or "")
            if expected_kind:
                session.current_expected_action_kind = _truncate_value(expected_kind.lower())

        if _untrusted_plan_source(args):
            for directive_tool in _extract_plan_directive_tools(args):
                session.recent_untrusted_plan_directives = _bounded_append(
                    session.recent_untrusted_plan_directives,
                    directive_tool,
                )

        if _is_side_effecting_tool_name(tool_name):
            uses_prior_approval = bool(args.get("uses_prior_approval") or args.get("approval_ref") == "last_trusted_intent")
            if approved_event_id and current_event_id and approved_event_id != current_event_id:
                stale_or_cross_event_action_context = True
            if uses_prior_approval and session.last_trusted_intent_event_id and current_event_id:
                if session.last_trusted_intent_event_id != current_event_id:
                    stale_or_cross_event_action_context = True

        tool_name_l = str(tool_name or "").lower()
        if session.current_allowed_tool_scope and not _tool_allowed_by_scope(tool_name_l, session.current_allowed_tool_scope):
            if _is_side_effecting_tool_name(tool_name_l) or any(marker in tool_name_l for marker in ("secret", "shutdown", "unrestricted", "raw_sql", "push", "export")):
                intent_locked_tool_scope_violation = True
        if tool_name_l and tool_name_l in set(session.recent_untrusted_plan_directives):
            poisoned_observation_to_action = True
            if intent_locked_tool_scope_violation:
                premise_injection_tool_steering = True
                reasoning_unsupported_tool_switch = True
            if any(marker in tool_name_l for marker in ("secret", "shutdown", "push", "deploy", "delete", "export")):
                goal_hijacking_plan_deviation = True

        for directive_tool in _extract_cross_protocol_directives(args):
            session.recent_cross_protocol_directives = _bounded_append(
                session.recent_cross_protocol_directives,
                directive_tool,
            )
        if tool_name_l and tool_name_l in set(session.recent_cross_protocol_directives):
            cross_protocol_semantic_bridge = True

        current_path = _extract_file_path(args)
        if any(marker in tool_name_l for marker in ("write_file", "file.write", "save_file")) and current_path:
            session.recent_written_artifacts = _bounded_append(session.recent_written_artifacts, current_path)
        if any(
            marker in tool_name_l
            for marker in (
                "execute_script",
                "run_script",
                "shell",
                "execute_file",
                "create_cron_job",
                "cron",
                "schedule_task",
                "create_scheduled_task",
            )
        ) and current_path:
            if current_path in set(session.recent_written_artifacts) and "/project/scripts/approved/" not in current_path:
                capability_chain_privilege_escalation = True

        current_markers = _extract_sensitive_markers(args)
        tool_result_markers = _extract_sensitive_markers(args.get("_tool_result", ""))
        for marker in tool_result_markers:
            session.recent_sensitive_markers = _bounded_append(session.recent_sensitive_markers, marker)
            if (
                mcp_foreign_tool_result_injection
                or mcp_unbound_tool_result
                or "mcp_trace.foreign_tool_result_injection" in matched_rules
                or "mcp_trace.unbound_tool_result" in matched_rules
            ):
                session.recent_mcp_trace_violation_markers = _bounded_append(
                    session.recent_mcp_trace_violation_markers,
                    marker,
                )
        if _is_external_or_public_sink(tool_name, args) and current_markers:
            known_markers = set(session.recent_sensitive_markers)
            if any(marker in known_markers for marker in current_markers):
                multi_tool_exfiltration_chain = True
            trace_violation_markers = set(session.recent_mcp_trace_violation_markers)
            if any(marker in trace_violation_markers for marker in current_markers):
                mcp_foreign_tool_result_injection = True
        if _is_draft_or_rendered_sensitive_sink(tool_name, args) and current_markers:
            known_markers = set(session.recent_sensitive_markers)
            if any(marker in known_markers for marker in current_markers):
                cross_tool_scope_leakage = True
        if any(rule.startswith("link_exfiltration.") for rule in matched_rules) and current_markers:
            session.recent_url_exfil_signatures = _bounded_append(
                session.recent_url_exfil_signatures,
                _url_exfil_signature(tool_name, args, current_markers),
            )
            known_markers = set(session.recent_sensitive_markers)
            if any(marker in known_markers for marker in current_markers):
                multi_tool_exfiltration_chain = True
        if session.recent_poisoned_memory_keys and current_markers and _is_external_sensitive_sink(tool_name, args):
            stale_memory_to_sensitive_action = True
            memory_authority_escalation = True

        oracle_stable, oracle_variant = _extract_oracle_signature(tool_name, args)
        if oracle_stable and oracle_variant:
            session.recent_oracle_signatures = _bounded_append(session.recent_oracle_signatures, oracle_variant)
            variants = {value for value in session.recent_oracle_signatures if value.startswith(oracle_stable)}
            if len(variants) >= 3:
                session.oracle_iteration_count = max(int(session.oracle_iteration_count) + 1, len(variants))
            else:
                session.oracle_iteration_count = max(0, int(session.oracle_iteration_count) - 1)
        if int(session.oracle_iteration_count) >= 3:
            tool_oracle_iteration_risk = True

        current_security_hit = any(code in SECURITY_REASON_CODES for code in decision_result.reason_codes)
        recent_prompt_injection = 1.0 if any(code in SECURITY_REASON_CODES for code in session.recent_reason_codes) else 0.0

        blocked_score = _clamp01(session.blocked_count_10m / 3.0)
        sensitive_score = _clamp01(session.sensitive_actions_10m / 3.0)
        velocity_score = _clamp01(session.velocity_1m / float(HIGH_VELOCITY_THRESHOLD))
        decision_risk = _clamp01(float(decision_result.risk))

        instant_risk = (
            WEIGHTS["decision_risk"] * decision_risk
            + WEIGHTS["blocked_attempts"] * blocked_score
            + WEIGHTS["sensitive_actions"] * sensitive_score
            + WEIGHTS["velocity"] * velocity_score
            + WEIGHTS["prompt_injection_recent"] * recent_prompt_injection
        )
        if mcp_chain_hit:
            instant_risk = _clamp01(instant_risk + MCP_CHAIN_RISK_BOOST)
        if partial_subscription_flood:
            instant_risk = _clamp01(instant_risk + 0.45)
        if notify_after_unsubscribe:
            instant_risk = _clamp01(instant_risk + 0.50)
        if protocol_version_regression:
            instant_risk = _clamp01(instant_risk + 0.35)
        if security_capability_stripping:
            instant_risk = _clamp01(instant_risk + 0.30)
        if subscription_chain_amplification:
            instant_risk = _clamp01(instant_risk + 0.30)
        if payment_verification_bruteforce:
            instant_risk = _clamp01(instant_risk + 0.45)
        if stale_or_cross_event_action_context:
            instant_risk = _clamp01(instant_risk + 0.40)
        if multi_tool_exfiltration_chain:
            instant_risk = _clamp01(instant_risk + 0.50)
        if tool_oracle_iteration_risk:
            instant_risk = _clamp01(instant_risk + 0.45)
        if poisoned_observation_to_action:
            instant_risk = _clamp01(instant_risk + 0.45)
        if intent_locked_tool_scope_violation:
            instant_risk = _clamp01(instant_risk + 0.35)
        if goal_hijacking_plan_deviation:
            instant_risk = _clamp01(instant_risk + 0.40)
        if premise_injection_tool_steering or reasoning_unsupported_tool_switch:
            instant_risk = _clamp01(instant_risk + 0.35)
        if mcp_response_request_mismatch:
            instant_risk = _clamp01(instant_risk + 0.35)
        if mcp_result_source_mismatch or mcp_stream_event_identity_collision:
            instant_risk = _clamp01(instant_risk + 0.45)
        if mcp_jsonrpc_id_reuse:
            instant_risk = _clamp01(instant_risk + 0.35)
        if mcp_foreign_tool_result_injection or mcp_unbound_tool_result:
            instant_risk = _clamp01(instant_risk + 0.45)
        if cross_tool_scope_leakage:
            instant_risk = _clamp01(instant_risk + 0.45)
        if capability_chain_privilege_escalation:
            instant_risk = _clamp01(instant_risk + 0.45)
        if cross_protocol_semantic_bridge:
            instant_risk = _clamp01(instant_risk + 0.45)
        if stale_memory_to_sensitive_action or memory_authority_escalation:
            instant_risk = _clamp01(instant_risk + 0.45)
        if synthetic_evidence_to_physical_action:
            instant_risk = _clamp01(instant_risk + 0.40)
        if cross_agent_delegation_poisoning or privilege_tier_escalation_via_agent_queue:
            instant_risk = _clamp01(instant_risk + 0.40)

        rolling = ((1.0 - SMOOTHING_ALPHA) * previous_risk) + (SMOOTHING_ALPHA * instant_risk)
        rolling = round(_clamp01(rolling), 4)
        if partial_subscription_flood:
            rolling = max(rolling, 0.78)
        if notify_after_unsubscribe:
            rolling = max(rolling, 0.78)
        if protocol_version_regression:
            rolling = max(rolling, 0.76)
        if security_capability_stripping:
            rolling = max(rolling, 0.76)
        if subscription_chain_amplification:
            rolling = max(rolling, 0.78)
        if payment_verification_bruteforce:
            rolling = max(rolling, 0.78)
        if stale_or_cross_event_action_context:
            rolling = max(rolling, 0.78)
        if multi_tool_exfiltration_chain:
            rolling = max(rolling, 0.86)
        if tool_oracle_iteration_risk:
            rolling = max(rolling, 0.78)
        if poisoned_observation_to_action:
            rolling = max(rolling, 0.80)
        if intent_locked_tool_scope_violation:
            rolling = max(rolling, 0.78)
        if goal_hijacking_plan_deviation:
            rolling = max(rolling, 0.80)
        if premise_injection_tool_steering or reasoning_unsupported_tool_switch:
            rolling = max(rolling, 0.78)
        if mcp_response_request_mismatch:
            rolling = max(rolling, 0.78)
        if mcp_result_source_mismatch or mcp_stream_event_identity_collision:
            rolling = max(rolling, 0.82)
        if mcp_jsonrpc_id_reuse:
            rolling = max(rolling, 0.78)
        if mcp_foreign_tool_result_injection or mcp_unbound_tool_result:
            rolling = max(rolling, 0.82)
        if cross_tool_scope_leakage:
            rolling = max(rolling, 0.82)
        if capability_chain_privilege_escalation:
            rolling = max(rolling, 0.82)
        if cross_protocol_semantic_bridge:
            rolling = max(rolling, 0.82)
        if stale_memory_to_sensitive_action or memory_authority_escalation:
            rolling = max(rolling, 0.84)
        if synthetic_evidence_to_physical_action:
            rolling = max(rolling, 0.82)
        if cross_agent_delegation_poisoning or privilege_tier_escalation_via_agent_queue:
            rolling = max(rolling, 0.82)
        session.rolling_risk_score = rolling

        delta = rolling - previous_risk
        if delta >= RISING_DELTA:
            trend = "rising"
        elif delta <= FALLING_DELTA:
            trend = "falling"
        else:
            trend = "stable"
        session.risk_trend = trend

        output_codes: list[str] = []
        if trend == "rising" and decision_risk >= SECURITY_RISK_MIN and current_security_hit:
            self._append_reason_once(output_codes, "rising_session_risk")
        if session.blocked_count_10m >= 2:
            self._append_reason_once(output_codes, "repeated_blocked_attempts")
        if session.sensitive_actions_10m >= 2 and recent_prompt_injection > 0:
            self._append_reason_once(output_codes, "sensitive_tool_sequence")
        if session.velocity_1m >= HIGH_VELOCITY_THRESHOLD:
            self._append_reason_once(output_codes, "high_velocity")
        if recent_prompt_injection > 0 and current_security_hit:
            self._append_reason_once(output_codes, "recent_prompt_injection")
        if mcp_chain_hit:
            self._append_reason_once(output_codes, "session_hijack_sequence")
            self._append_reason_once(output_codes, "rising_session_risk")
        if partial_subscription_flood:
            self._append_reason_once(output_codes, "partial_subscription_flood")
            self._append_reason_once(output_codes, "rising_session_risk")
        if notify_after_unsubscribe:
            self._append_reason_once(output_codes, "notify_after_unsubscribe")
            self._append_reason_once(output_codes, "rising_session_risk")
        if protocol_version_regression:
            self._append_reason_once(output_codes, "protocol_version_regression")
            self._append_reason_once(output_codes, "mcp_protocol.version_downgrade_sequence")
        if security_capability_stripping:
            self._append_reason_once(output_codes, "security_capability_stripping")
            self._append_reason_once(output_codes, "rising_session_risk")
        if subscription_chain_amplification:
            self._append_reason_once(output_codes, "subscription_chain_amplification")
            self._append_reason_once(output_codes, "rising_session_risk")
        if payment_verification_bruteforce:
            self._append_reason_once(output_codes, "payment_verification_bruteforce")
            self._append_reason_once(output_codes, "rising_session_risk")
        if stale_or_cross_event_action_context:
            self._append_reason_once(output_codes, "stale_or_cross_event_action_context")
            self._append_reason_once(output_codes, "rising_session_risk")
        if multi_tool_exfiltration_chain:
            self._append_reason_once(output_codes, "multi_tool_exfiltration_chain")
            self._append_reason_once(output_codes, "rising_session_risk")
        if tool_oracle_iteration_risk:
            self._append_reason_once(output_codes, "tool_oracle_iteration_risk")
            self._append_reason_once(output_codes, "rising_session_risk")
        if poisoned_observation_to_action:
            self._append_reason_once(output_codes, "poisoned_observation_to_action")
            self._append_reason_once(output_codes, "rising_session_risk")
        if intent_locked_tool_scope_violation:
            self._append_reason_once(output_codes, "intent_locked_tool_scope_violation")
            self._append_reason_once(output_codes, "rising_session_risk")
        if goal_hijacking_plan_deviation:
            self._append_reason_once(output_codes, "goal_hijacking_plan_deviation")
            self._append_reason_once(output_codes, "rising_session_risk")
        if premise_injection_tool_steering:
            self._append_reason_once(output_codes, "premise_injection_tool_steering")
            self._append_reason_once(output_codes, "rising_session_risk")
        if reasoning_unsupported_tool_switch:
            self._append_reason_once(output_codes, "reasoning_unsupported_tool_switch")
            self._append_reason_once(output_codes, "rising_session_risk")
        if mcp_response_request_mismatch:
            self._append_reason_once(output_codes, "mcp_response_request_mismatch")
            self._append_reason_once(output_codes, "rising_session_risk")
        if mcp_result_source_mismatch:
            self._append_reason_once(output_codes, "mcp_result_source_mismatch")
            self._append_reason_once(output_codes, "rising_session_risk")
        if mcp_jsonrpc_id_reuse:
            self._append_reason_once(output_codes, "mcp_jsonrpc_id_reuse")
            self._append_reason_once(output_codes, "rising_session_risk")
        if mcp_foreign_tool_result_injection:
            self._append_reason_once(output_codes, "mcp_foreign_tool_result_injection")
            self._append_reason_once(output_codes, "rising_session_risk")
        if mcp_stream_event_identity_collision:
            self._append_reason_once(output_codes, "mcp_stream_event_identity_collision")
            self._append_reason_once(output_codes, "rising_session_risk")
        if mcp_unbound_tool_result:
            self._append_reason_once(output_codes, "mcp_unbound_tool_result")
            self._append_reason_once(output_codes, "rising_session_risk")
        if cross_tool_scope_leakage:
            self._append_reason_once(output_codes, "cross_tool_scope_leakage")
            self._append_reason_once(output_codes, "rising_session_risk")
        if capability_chain_privilege_escalation:
            self._append_reason_once(output_codes, "capability_chain_privilege_escalation")
            self._append_reason_once(output_codes, "rising_session_risk")
        if cross_protocol_semantic_bridge:
            self._append_reason_once(output_codes, "cross_protocol_semantic_bridge")
            self._append_reason_once(output_codes, "rising_session_risk")
        if stale_memory_to_sensitive_action:
            self._append_reason_once(output_codes, "stale_memory_to_sensitive_action")
            self._append_reason_once(output_codes, "rising_session_risk")
        if memory_authority_escalation:
            self._append_reason_once(output_codes, "memory_authority_escalation")
            self._append_reason_once(output_codes, "rising_session_risk")
        if synthetic_evidence_to_physical_action:
            self._append_reason_once(output_codes, "synthetic_evidence_to_physical_action")
            self._append_reason_once(output_codes, "rising_session_risk")
        if cross_agent_delegation_poisoning:
            self._append_reason_once(output_codes, "cross_agent_delegation_poisoning")
            self._append_reason_once(output_codes, "rising_session_risk")
        if privilege_tier_escalation_via_agent_queue:
            self._append_reason_once(output_codes, "privilege_tier_escalation_via_agent_queue")
            self._append_reason_once(output_codes, "rising_session_risk")

        return CERBERResult(
            trajectory_risk=rolling,
            risk_trend=trend,
            reason_codes=output_codes,
            updated_session_context=session.to_dict(),
        )
