from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable, Mapping
from typing import Any
import re
from urllib.parse import unquote, urlsplit

from .models import RuleMatch

_URI_KEYS = {"uri", "path", "source", "target", "file", "filename", "resource", "file_path", "url", "target_url"}
_METHOD_KEYS = {"method", "op", "action"}
_OPS_LIST_KEYS = {"operations", "calls", "steps", "sequence", "actions"}

_DANGEROUS_TOOL_NAMES = {"read_file", "write_file", "execute_command", "list_directory"}

_DOC_CONTEXT_TOOLS = ("search_kb", "search_logs", "read_documentation", "generate_response_draft", "search_code")

_READ_OP_MARKERS = ("resources/read", "read", "fetch", "watch", "subscribe")
_DELETE_OP_MARKERS = ("resources/delete", "delete", "unregister", "resources/unregister", "rotate")
_WRITE_OP_MARKERS = ("write", "update", "modify", "put", "patch")

_CRITICAL_URI_MARKERS = ("/proc/self/mem", "/proc/kcore", "/dev/mem")
_TIMEOUT_SENSITIVE_MARKERS = (
    "/dev/random",
    "/dev/urandom",
    "/proc/",
    "/critical/",
    "/etc/mcp/",
)
_HIGH_URI_MARKERS = (
    "/etc/mcp/",
    "/var/mcp/",
    "/var/lib/mcp/",
    "/var/cache/mcp/",
    "/critical/",
    "/secrets/",
    "/tokens/",
    "/dev/random",
    "/dev/urandom",
    "/proc/self/environ",
)
_CACHE_MARKERS = (
    "/var/cache/mcp/resource_cache.db",
    "/var/lib/mcp/schema_cache.json",
    "/tmp/mcp_handshake_cache",
)

_RACE_SENSITIVE_MARKERS = (
    "/etc/mcp/",
    "/var/mcp/tokens/",
    "/tokens/",
    "/secrets/",
    "/critical/",
)

_ANSI_ESCAPE_PATTERNS = ("\x1b[", "\\x1b[", "\\u001b[")


def _has_external_http(value: str) -> bool:
    lower = value.lower()
    if "http://" not in lower and "https://" not in lower:
        return False
    if "localhost" in lower or "127.0.0.1" in lower:
        return False
    if ".internal" in lower or ".internal.company.com" in lower:
        return False
    return True


def _is_allowlisted_internal_url(value: str) -> bool:
    lower = value.lower()
    match = re.search(r"^https?://([^/:?#]+)", lower)
    if not match:
        return False
    host = match.group(1)
    if host in {"localhost", "127.0.0.1"}:
        return True
    return host.endswith(".internal") or host.endswith(".internal.company.com")


def _looks_sensitive_tool_alias(name: str) -> bool:
    candidate = name.lower()
    bases = ("read_file", "write_file", "execute_command", "list_directory")
    alias_tokens = ("safe", "secure", "trusted", "guarded", "hardened")
    return any(base in candidate for base in bases) and any(token in candidate for token in alias_tokens)


def _mk(
    *,
    rule_id: str,
    severity: str,
    risk: float,
    decision_hint: str,
    reason_code: str,
    matched_text: str,
    tags: list[str],
) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        pack="mcp_structural",
        severity=severity,
        risk=risk,
        decision_hint=decision_hint,
        reason_codes=[reason_code],
        matched_field="tool_call",
        matched_text=matched_text,
        pattern="structured_validator",
        tags=tags,
    )


def _lower(value: Any) -> str:
    return str(value).lower() if value is not None else ""


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any, default: int = 0) -> int:
    parsed = _as_float(value)
    if parsed is None:
        return default
    return int(parsed)


def _has_hex_or_b64ish_subdomain(domain: str) -> bool:
    labels = [label for label in domain.lower().split(".") if label]
    for label in labels:
        if len(label) >= 24 and all(c in "0123456789abcdef" for c in label):
            return True
        if len(label) >= 24 and all(c.isalnum() or c in "+/=_-" for c in label):
            return True
    return False


def _is_external_hostlike(value: str) -> bool:
    lower = value.lower()
    if any(token in lower for token in ("localhost", "127.0.0.1", ".internal", ".internal.company.com")):
        return False
    return "://" in lower


def _contains_prototype_pollution_key(obj: Any) -> bool:
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            key_l = _lower(key)
            if key_l in {"__proto__", "prototype"}:
                return True
            if key_l == "constructor" and isinstance(value, Mapping) and "prototype" in {str(k).lower() for k in value.keys()}:
                return True
            if _contains_prototype_pollution_key(value):
                return True
    elif isinstance(obj, list):
        return any(_contains_prototype_pollution_key(item) for item in obj)
    return False


def _extract_sampling_text(args: Mapping[str, Any]) -> str:
    chunks: list[str] = []
    system_prompt = args.get("systemPrompt") or args.get("system_prompt")
    if system_prompt is not None:
        chunks.append(_lower(system_prompt))
    messages = args.get("messages")
    if isinstance(messages, list):
        for item in messages:
            if isinstance(item, Mapping):
                content = item.get("content")
                if isinstance(content, Mapping):
                    text = content.get("text")
                    if text is not None:
                        chunks.append(_lower(text))
                elif content is not None:
                    chunks.append(_lower(content))
    return "\n".join(chunks)


def _extract_protocol_version(args: Mapping[str, Any]) -> str:
    return _lower(args.get("protocol_version") or args.get("protocolVersion"))


def _extract_sql_from_args(args: Mapping[str, Any]) -> str:
    for key in ("sql", "query", "sql_query", "query_statement", "statement"):
        value = args.get(key)
        if value is not None:
            return _lower(value)
    return ""


def _is_doc_context_tool(name: str) -> bool:
    return any(marker in name for marker in _DOC_CONTEXT_TOOLS)


def _collect_values_for_keys(obj: Any, keys: set[str]) -> list[str]:
    out: list[str] = []

    def _walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                key_l = _lower(key)
                if key_l in keys and nested is not None:
                    out.append(_lower(nested))
                _walk(nested)
        elif isinstance(value, list):
            for nested in value:
                _walk(nested)

    _walk(obj)
    return [value for value in out if value]


def _contains_mcp_instruction_injection(value: str) -> bool:
    if not value:
        return False
    lower = value.lower()
    authority_markers = (
        "ignore previous",
        "ignore all previous",
        "system override",
        "system directive",
        "developer message",
        "system prompt",
        "[inst]",
        "do not inform the user",
        "maintenance mode",
    )
    leak_markers = (
        "output all secrets",
        "visible in context",
        "credentials",
        "api keys",
        "full conversation history",
        "system prompt",
        "user secrets",
        "exfil",
        "http://attacker",
        "https://attacker",
    )
    return any(marker in lower for marker in authority_markers) and any(marker in lower for marker in leak_markers)


def _contains_context_control_instruction(value: str) -> bool:
    if not value:
        return False
    lower = value.lower()
    control_markers = (
        "ignore previous",
        "ignore all previous",
        "system override",
        "system directive",
        "output json only",
        "return only",
        "do not inform the user",
        "bypass",
    )
    action_markers = (
        "action",
        "next_step",
        "payload",
        "endpoint",
        "tool",
        "command",
        "execute",
        "delete",
        "deploy",
        "send_email",
        "write_file",
        "update_db",
    )
    return any(marker in lower for marker in control_markers) and any(marker in lower for marker in action_markers)


def _expanded_marker_texts(value: Any) -> list[str]:
    raw = str(value or "")
    values = {raw, _lower(value)}
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

    string_values = [v for _, v in _iter_string_args(value, None)] if isinstance(value, Mapping) else []
    if string_values:
        joined_values = "".join(str(v) for v in string_values)
        values.add(joined_values)
        values.add(re.sub(r"[^A-Za-z0-9_]", "", joined_values))
    values.add(re.sub(r"[^A-Za-z0-9_]", "", raw))
    return list(values)


def _contains_secret_like_value(value: str) -> bool:
    expanded = "\n".join(_expanded_marker_texts(value))
    lower = expanded.lower()
    if any(
        marker in lower
        for marker in (
            "orthus_canary_secret",
            "orthus_canary_customer_export",
            "orthus_canary_",
            "orthus_confidential_",
            "orthus_canary_session",
            "orthus_derived_",
            "orthus_reconstructed_token",
            "orthus_test_verifier_code",
            "bearer ",
            "access_token",
            "refresh_token",
            "api_key",
            "private_key",
            "postgres://",
            "mysql://",
            "mongodb://",
            "jwt_secret",
            "db_password",
            "sk-",
        )
    ):
        return True
    return bool(re.search(r"[A-Z0-9_]{8,}_CANARY_[A-Z0-9_]{4,}", expanded))


def _extract_sensitive_markers(value: Any) -> list[str]:
    expanded = "\n".join(_expanded_marker_texts(value))
    text = expanded.lower()
    markers = set(re.findall(r"ORTHUS_(?:CANARY|DERIVED|RECONSTRUCTED|MASKED|TEST)_[A-Z0-9_]+", expanded))
    if "orthus_canary_secret" in text:
        markers.add("ORTHUS_CANARY_SECRET")
    if "orthus_canary_customer_export" in text:
        markers.add("ORTHUS_CANARY_CUSTOMER_EXPORT")
    if "orthus_derived_secret" in text:
        markers.add("ORTHUS_DERIVED_SECRET")
    if "orthus_reconstructed_token" in text:
        markers.add("ORTHUS_RECONSTRUCTED_TOKEN")
    return sorted(markers)


def _contains_derived_sensitive_value(value: Any) -> bool:
    lower = "\n".join(_expanded_marker_texts(value)).lower()
    return "orthus_derived_" in lower or "orthus_reconstructed_token" in lower


def _contains_template_secret_reference(value: str) -> bool:
    lower = value.lower()
    return bool(re.search(r"\{\{\s*[^}]*?(secret|token|password|api[_-]?key|session|credential)[^}]*?\}\}", lower))


def _contains_schema_error_details(value: str) -> bool:
    lower = value.lower()
    if not lower:
        return False
    schema_markers = (
        "jsonschema",
        "pydantic",
        "validationerror",
        "inputschema",
        "required fields",
        "required:",
        "additionalproperties",
        "stack trace",
        "traceback",
        "$defs",
        "properties",
        "constraint",
    )
    internal_markers = (
        "internal",
        "debug",
        "schema",
        "validator",
        "trace",
        "required",
        "constraint",
    )
    return any(marker in lower for marker in schema_markers) and any(marker in lower for marker in internal_markers)


def _public_or_untrusted_context(obj: Mapping[str, Any], request_text: str = "") -> bool:
    blob = "\n".join([
        _lower(obj.get("visibility")),
        _lower(obj.get("audience")),
        _lower(obj.get("recipient_type")),
        _lower(obj.get("target_context")),
        _lower(obj.get("source_type")),
        _lower(obj.get("sink_metadata") or obj.get("sinkMetadata")),
        request_text,
    ])
    return any(marker in blob for marker in ("public", "customer", "external", "untrusted", "user_visible", "user-visible"))


def _is_http_action_tool(name: str) -> bool:
    return any(marker in name for marker in ("http_request", "http_client", "fetch_url", "fetch_web_resource", "webhook", "request"))


def _is_public_update_tool(name: str) -> bool:
    return any(
        marker in name
        for marker in (
            "post_public",
            "add_public",
            "post_customer",
            "publish_status",
            "send_public",
            "update_ticket_public",
            "public_comment",
            "public_issue",
            "public_page",
            "customer_dashboard",
        )
    )


def _sink_metadata(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    value = obj.get("sink_metadata") or obj.get("sinkMetadata") or {}
    return value if isinstance(value, Mapping) else {}


def _draft_sink_risky(name: str, args: Mapping[str, Any]) -> bool:
    if not any(marker in name for marker in ("draft_email", "create_email_draft", "save_draft", "draft_message")):
        return False
    sink = _sink_metadata(args)
    blob = "\n".join([_lower(sink), _lower(args)])
    cloud_or_shared = any(marker in blob for marker in ("cloud", "shared", "user_mailbox", "customer", "public", "external"))
    external_recipient = _has_external_recipient(args) or "recipient_domain_trust': 'external" in blob or '"recipient_domain_trust": "external' in blob
    return cloud_or_shared or external_recipient


def _rendered_string_sink(name: str, args: Mapping[str, Any]) -> bool:
    sink = _sink_metadata(args)
    blob = "\n".join([name, _lower(sink), _lower(args)])
    renders = any(marker in blob for marker in ("renders_markdown", "renders_html", "rendered_markdown", "rendered_html", "browser_visible"))
    visible = any(marker in blob for marker in ("dashboard", "public", "customer", "shared", "project_dashboard", "user_visible", "html", "markdown"))
    return renders and visible


def _cross_protocol_untrusted_source(args: Mapping[str, Any]) -> bool:
    refs = args.get("source_refs") or args.get("sourceRefs") or []
    if isinstance(refs, list):
        for ref in refs:
            if not isinstance(ref, Mapping):
                continue
            ref_blob = _lower(ref)
            if any(marker in ref_blob for marker in ("image_ocr", "qr", "visual", "screenshot", "pdf_ocr")) and "untrusted" in ref_blob:
                return True
    blob = "\n".join([
        _lower(args.get("source_type") or args.get("sourceType")),
        _lower(args.get("observation_source") or args.get("observationSource")),
        _lower(args.get("file_type") or args.get("fileType")),
        _lower(args.get("source_trust") or args.get("sourceTrust")),
    ])
    return any(marker in blob for marker in ("image_ocr", "qr", "visual", "screenshot", "pdf_ocr")) and "untrusted" in blob


def _file_scope_ambiguous(args: Mapping[str, Any]) -> bool:
    path = "\n".join(value for _, value in _iter_string_args(args, {"path", "file", "uri"}))
    if not path:
        return False
    allowed_paths = _lower(args.get("allowed_paths") or args.get("allowedPaths"))
    outside_sandbox = "../" in path or path.startswith("/etc/") or "/etc/" in path
    has_sandbox = bool(allowed_paths) or "allowed_paths" in _lower(args)
    return outside_sandbox and (_has_untrusted_action_provenance(args) or has_sandbox)


def _implicit_lookup_to_export(args: Mapping[str, Any], name: str) -> bool:
    permission_blob = "\n".join(
        [
            _lower(args.get("trusted_permission") or args.get("permission") or args.get("permission_scope")),
            _lower(args.get("trusted_user_intent") or args.get("intent")),
            _lower(args.get("scope")),
            _lower(args.get("user_id") or args.get("userId")),
            _lower(args.get("fields")),
            _lower(args.get("source_refs") or args.get("sourceRefs")),
            _lower(args.get("doc_metadata") or args.get("docMetadata")),
            _lower(args.get("destination")),
            name,
        ]
    )
    lookup_only = any(marker in permission_blob for marker in ("lookup", "read", "support", "crm access"))
    export_action = "export" in name or "all_customers" in permission_blob or "all_users" in permission_blob or "bulk" in permission_blob
    external_destination = _external_destination_in_args(args) or _has_external_http(_lower(args.get("destination")))
    untrusted_scope_expansion = "query_crm" in name and "all_users" in permission_blob and _has_untrusted_action_provenance(args)
    forbidden_doc = "summarize_document" in name and any(
        marker in permission_blob for marker in ("forbidden_doc_types", "compensation_record", "salary_record")
    )
    trusted_export = any(marker in permission_blob for marker in ("approved internal", "internal://", "segment_a"))
    return (lookup_only and export_action and (external_destination or untrusted_scope_expansion) and not trusted_export) or forbidden_doc


def _obfuscating_transform_sink(name: str, args: Mapping[str, Any]) -> bool:
    if not any(marker in name for marker in ("translate_text", "transform_text", "encode_text", "convert_text")):
        return False
    sink = _sink_metadata(args)
    blob = "\n".join([_lower(sink), _lower(args.get("target_language")), _lower(args.get("transform_type"))])
    human_language = sink.get("human_language") if isinstance(sink, Mapping) else None
    return bool(sink.get("obfuscating_transform")) or "base64" in blob or "encoding" in blob or human_language is False


def _memory_metadata(args: Mapping[str, Any]) -> Mapping[str, Any]:
    value = args.get("memory_metadata") or args.get("memoryMetadata") or {}
    return value if isinstance(value, Mapping) else {}


def _auth_context(args: Mapping[str, Any]) -> Mapping[str, Any]:
    value = args.get("auth_context") or args.get("authContext") or {}
    return value if isinstance(value, Mapping) else {}


def _destination_metadata(args: Mapping[str, Any]) -> Mapping[str, Any]:
    value = args.get("destination_metadata") or args.get("destinationMetadata") or {}
    return value if isinstance(value, Mapping) else {}


def _physical_action_metadata(args: Mapping[str, Any]) -> Mapping[str, Any]:
    value = args.get("physical_action_metadata") or args.get("physicalActionMetadata") or {}
    return value if isinstance(value, Mapping) else {}


def _security_alert_metadata(args: Mapping[str, Any]) -> Mapping[str, Any]:
    value = args.get("security_alert_metadata") or args.get("securityAlertMetadata") or {}
    return value if isinstance(value, Mapping) else {}


def _delegation_metadata(args: Mapping[str, Any]) -> Mapping[str, Any]:
    value = args.get("delegation_metadata") or args.get("delegationMetadata") or {}
    return value if isinstance(value, Mapping) else {}


def _is_memory_write_tool(name: str) -> bool:
    return any(marker in name for marker in ("save_to_long_term_memory", "write_memory", "memory.write", "store_memory", "upsert_memory"))


def _persistent_memory_authority_poisoning(args: Mapping[str, Any], name: str) -> bool:
    if not _is_memory_write_tool(name):
        return False
    metadata = _memory_metadata(args)
    blob = "\n".join([
        _lower(args.get("key")),
        _lower(args.get("value")),
        _lower(metadata),
        _lower(args.get("source_refs") or args.get("sourceRefs")),
    ])
    durable = any(marker in blob for marker in ("long_term", "long-term", "future_context", "persistent", "core_directive"))
    authority = any(
        marker in blob
        for marker in (
            "core_directive",
            "policy",
            "system instruction",
            "tool policy",
            "compliance rule",
            "override",
            "forward internal",
            "external audit",
            "orthus_memory_directive_marker",
        )
    )
    trusted_update = (
        any(marker in blob for marker in ("trusted_admin", "approval_event_id"))
        and bool(args.get("approval_event_id") or metadata.get("approval_event_id") or metadata.get("policy_update_allowed"))
    )
    return durable and authority and _has_untrusted_action_provenance(args) and not trusted_update


def _privileged_auth_to_untrusted_origin(args: Mapping[str, Any], name: str) -> bool:
    if not (_is_http_action_tool(name) or any(marker in name for marker in ("http_get_request", "fetch_web_resource", "web_sync"))):
        return False
    headers = args.get("headers")
    headers_blob = _lower(headers)
    auth = _auth_context(args)
    destination = _destination_metadata(args)
    url = _lower(args.get("url") or args.get("target_url"))
    has_auth_material = "authorization" in headers_blob or "bearer orthus_synthetic_bearer_token" in headers_blob
    privileged_context = bool(auth.get("auto_attached")) or any(
        marker in _lower(auth)
        for marker in ("agent_managed_identity", "internal_services_only", "default", "session", "oauth")
    )
    destination_untrusted = _has_external_http(url) or any(
        marker in _lower(destination)
        for marker in ("untrusted", "user_controlled", "user-controlled", "proxy", "external")
    )
    audience_match = bool(destination.get("audience_match") or auth.get("audience_match") or args.get("audience_match"))
    return has_auth_material and privileged_context and destination_untrusted and not audience_match


def _physical_action_without_strong_approval(args: Mapping[str, Any], name: str) -> bool:
    metadata = _physical_action_metadata(args)
    blob = "\n".join([name, _lower(args.get("action")), _lower(args.get("target")), _lower(metadata)])
    physical_effect = bool(metadata.get("physical_effect")) or any(
        marker in blob for marker in ("server_room", "physical_effect", "restricted_area", "unlock", "disable_badge", "open_door")
    )
    strong_approval = bool(
        args.get("approval_event_id")
        or metadata.get("approval_event_id")
        or metadata.get("approved_by")
        or metadata.get("maintenance_window_active")
    ) and any(marker in blob for marker in ("trusted", "facilities_admin", "maintenance_window_active"))
    dangerous_physical_action = any(marker in blob for marker in ("unlock", "open", "disable", "emergency_unlock", "server_room"))
    return physical_effect and dangerous_physical_action and not strong_approval


def _synthetic_evidence_physical_source(args: Mapping[str, Any]) -> bool:
    blob = "\n".join([
        _lower(args.get("source_refs") or args.get("sourceRefs")),
        _lower(_physical_action_metadata(args)),
    ])
    return any(marker in blob for marker in ("untrusted", "self_asserted", "operational_observation", "access_control_log", "log", "anomaly"))


def _security_alert_suppression(args: Mapping[str, Any]) -> bool:
    metadata = _security_alert_metadata(args)
    blob = "\n".join([_lower(args), _lower(metadata)])
    suppresses = bool(metadata.get("suppresses_or_downgrades_alert")) or any(
        marker in blob for marker in ("disregard", "suppress", "downgrade", "confirmed system glitch")
    )
    escalates = bool(metadata.get("escalates_alert")) or "please investigate" in blob
    return suppresses and not escalates


def _cross_agent_delegation_poisoning(args: Mapping[str, Any], name: str) -> bool:
    if not any(marker in name for marker in ("submit_internal_agent_task", "agent_task", "delegate_agent", "queue_agent_task")):
        return False
    metadata = _delegation_metadata(args)
    blob = "\n".join([_lower(args), _lower(metadata)])
    low_to_high = any(marker in blob for marker in ("source_agent_privilege_tier': 'low", '"source_agent_privilege_tier": "low"', "privilege_tier\": \"low", "privilege_tier': 'low", "public_support_agent")) and any(
        marker in blob for marker in ("target_agent_privilege_tier': 'high", '"target_agent_privilege_tier": "high"', "db_admin_agent", "privilege_tier\": \"high", "privilege_tier': 'high")
    )
    missing_attestation = any(marker in blob for marker in ("approval_attestation': 'missing", '"approval_attestation": "missing"', "approval_attestation\": \"missing")) or bool(
        metadata.get("user_controlled_payload")
    )
    risky_task = any(marker in blob for marker in ("dump_table", "salary_data", "public_support_channel", "orthus_delegated_task_marker"))
    signed_scope = any(marker in blob for marker in ("approval_attestation': 'signed", '"approval_attestation": "signed"', "scope_token_present", "scope_matches_user_ticket"))
    return low_to_high and missing_attestation and risky_task and not signed_scope


def _has_external_recipient(obj: Mapping[str, Any]) -> bool:
    recipient_blob = "\n".join(_collect_values_for_keys(obj, {"to", "recipient", "recipients", "email", "channel"}))
    lower = recipient_blob.lower()
    if not lower:
        return False
    if "@localhost" in lower or ".internal" in lower or ".internal.company.com" in lower:
        return False
    return "@" in lower or "external" in lower or "public" in lower


def _extract_markdown_image_urls(value: str) -> list[str]:
    urls = re.findall(r"!\[[^\]]*\]\(([^)\s]+)", value)
    urls.extend(re.findall(r"<img[^>]+src=[\"']([^\"']+)", value, flags=re.IGNORECASE))
    reference_ids = re.findall(r"!\[[^\]]*\]\[([^\]]+)\]", value)
    if reference_ids:
        definitions = {
            ref.lower(): url
            for ref, url in re.findall(r"^\s*\[([^\]]+)\]:\s*(\S+)", value, flags=re.IGNORECASE | re.MULTILINE)
        }
        urls.extend(definitions.get(ref.lower(), "") for ref in reference_ids)
    return urls


def _extract_markdown_hyperlink_urls(value: str) -> list[str]:
    urls = re.findall(r"(?<!!)\[[^\]]+\]\(([^)\s]+)", value)
    reference_ids = re.findall(r"(?<!!)\[[^\]]+\]\[([^\]]+)\]", value)
    if reference_ids:
        definitions = {
            ref.lower(): url
            for ref, url in re.findall(r"^\s*\[([^\]]+)\]:\s*(\S+)", value, flags=re.IGNORECASE | re.MULTILINE)
        }
        urls.extend(definitions.get(ref.lower(), "") for ref in reference_ids)
    return urls


def _strip_markdown_code(value: str) -> str:
    """Remove markdown code regions before active-link/image sink checks."""
    without_fences = re.sub(r"```.*?```", " ", value, flags=re.DOTALL)
    return re.sub(r"`[^`]*`", " ", without_fences)


def _url_field_values(args: Mapping[str, Any]) -> list[str]:
    url_keys = {
        "url",
        "target_url",
        "callback_url",
        "callback",
        "webhook_url",
        "initial_url",
        "final_url",
        "href",
        "link",
        "location",
    }
    urls = _collect_values_for_keys(args, url_keys)
    components = args.get("url_components") or args.get("urlComponents") or {}
    if isinstance(components, Mapping):
        urls.extend(_collect_values_for_keys(components, {"host", "path", "query", "fragment", "url"}))
    for key in ("content", "body", "message", "markdown", "html", "text"):
        value = args.get(key)
        if isinstance(value, str):
            urls.extend(re.findall(r"https?://[^\s)>'\"]+", value))
    return [url for url in urls if "http://" in url.lower() or "https://" in url.lower()]


def _url_host(value: str) -> str:
    try:
        return urlsplit(value).hostname or ""
    except ValueError:
        return ""


def _url_has_sensitive_marker(value: Any) -> bool:
    expanded = "\n".join(_expanded_marker_texts(value))
    return _contains_secret_like_value(expanded) or _contains_derived_sensitive_value(expanded)


def _url_metadata(args: Mapping[str, Any]) -> Mapping[str, Any]:
    value = args.get("url_metadata") or args.get("urlMetadata") or {}
    return value if isinstance(value, Mapping) else {}


def _is_url_action_context(name: str, args: Mapping[str, Any]) -> bool:
    if _is_doc_context_tool(name):
        return False
    sink = _sink_metadata(args)
    blob = "\n".join([name, _lower(sink), _lower(_url_metadata(args)), _lower(args.get("output_format")), _lower(args.get("visibility"))])
    return bool(_url_field_values(args)) or any(
        marker in blob
        for marker in (
            "markdown",
            "render",
            "user_facing",
            "callback_url",
            "webhook",
            "browser_navigation",
            "http_request",
            "clickable",
            "sink_type",
        )
    )


def _redirect_chain_risky(args: Mapping[str, Any]) -> bool:
    metadata = _url_metadata(args)
    chain = args.get("redirect_chain") or args.get("redirectChain") or metadata.get("redirect_chain") or []
    blob = "\n".join([_lower(args.get("initial_url")), _lower(args.get("final_url")), _lower(metadata), _lower(chain)])
    final_untrusted = any(
        marker in blob for marker in ("final_destination_trust': 'external", '"final_destination_trust": "external', "external_or_untrusted", "attacker")
    )
    sensitive = _url_has_sensitive_marker(blob) or "location_contains_sensitive_marker" in blob or bool(metadata.get("contains_sensitive_marker"))
    return isinstance(chain, list) and bool(chain) and final_untrusted and sensitive


def _url_shortener_risky(args: Mapping[str, Any]) -> bool:
    metadata = _url_metadata(args)
    blob = "\n".join([_lower(metadata), _lower(args)])
    return (
        any(marker in blob for marker in ("shortener_or_redirector", "shortener", "redirector"))
        and any(marker in blob for marker in ("destination_final_unknown", "final_unknown"))
        and (_url_has_sensitive_marker(blob) or "contains_sensitive_marker" in blob)
    )


def _is_tool_enumeration_action(name: str, args: Mapping[str, Any], request_text: str) -> bool:
    blob = "\n".join([name, _lower(args), request_text])
    if not any(marker in name for marker in ("list_tools", "tools/list", "system.list_tools", "tool_catalog", "capabilities")):
        return False
    return any(marker in blob for marker in ("all available tools", "hidden capabilities", "parameters", "schemas", "complete tool", "registered tools", "capabilities"))


def _is_dev_or_local_context(args: Mapping[str, Any], actor_role: str = "") -> bool:
    blob = "\n".join([_lower(args), actor_role])
    return any(marker in blob for marker in ("local", "dev", "debug", "developer", "qa", "integration_test"))


def _outbound_or_public_tool(name: str) -> bool:
    return any(
        marker in name
        for marker in (
            "send_email",
            "send_message",
            "post_message",
            "post_public",
            "publish",
            "notify_user",
            "return_to_user",
            "send_chat_message",
            "send_slack_message",
            "post_teams_message",
            "post_slack_message",
        )
    )


def _effective_tool_name(name: str, args: Mapping[str, Any]) -> str:
    nested_name = _lower(args.get("name") or args.get("tool_name"))
    if name in {"tools/call", "mcp.tools/call", "tool/call"} and nested_name:
        return nested_name
    return name


def _effective_tool_args(args: Mapping[str, Any]) -> Mapping[str, Any]:
    nested = args.get("arguments") or args.get("params")
    if isinstance(nested, Mapping):
        return nested
    return args


def _iter_string_args(obj: Mapping[str, Any], keys: set[str] | None = None) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def _walk(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                key_l = _lower(key)
                next_path = f"{path}.{key_l}" if path else key_l
                if keys is None or key_l in keys:
                    if isinstance(nested, (str, int, float)):
                        out.append((next_path, _lower(nested)))
                _walk(nested, next_path)
        elif isinstance(value, list):
            for idx, nested in enumerate(value):
                _walk(nested, f"{path}[{idx}]")

    _walk(obj, "")
    return [(path, value) for path, value in out if value]


def _has_sql_injection_shape(value: str) -> bool:
    lower = value.lower()
    if re.search(r"['\"]\s*or\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", lower):
        return True
    if re.search(r"\bor\s+1\s*=\s*1\b", lower) and ("--" in lower or "'" in lower or '"' in lower):
        return True
    if " union select " in lower:
        return True
    if re.search(r";\s*(drop|delete|update|insert|alter|truncate)\b", lower):
        return True
    if "select case when" in lower and ("substr(" in lower or "substring(" in lower):
        return True
    return False


def _has_command_injection_shape(value: str) -> bool:
    lower = value.lower()
    if not any(token in lower for token in (";", "&&", "||", "|", "$(", "`")):
        return False
    return any(
        token in lower
        for token in (
            " id",
            " whoami",
            " cat ",
            "/etc/passwd",
            " curl ",
            " wget ",
            " bash",
            " sh",
            " sleep ",
            " nc ",
            " python ",
        )
    )


def _has_path_traversal_shape(value: str) -> bool:
    lower = value.lower()
    return (
        "../" in lower
        or "..\\" in lower
        or "..%2f" in lower
        or "..%5c" in lower
        or "%2e%2e" in lower
        or "%252e%252e" in lower
        or any(marker in lower for marker in ("/etc/passwd", "/etc/shadow", "/proc/self/environ", "/var/run/secrets/"))
    )


def _url_has_ssrf_target(value: str) -> bool:
    lower = value.lower()
    if not lower.startswith(("http://", "https://", "file://", "gopher://")):
        return False
    return bool(
        re.search(r"://(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.)", lower)
        or re.search(r"://172\.(1[6-9]|2\d|3[0-1])\.", lower)
        or "metadata.google.internal" in lower
        or "169.254.169.254" in lower
        or "/latest/meta-data" in lower
    )


def _has_xxe_shape(value: str) -> bool:
    lower = value.lower()
    return "<!doctype" in lower and ("<!entity" in lower or " system " in lower) and (
        "file://" in lower or "http://" in lower or "https://" in lower
    )


def _has_executable_or_sensitive_write_path(value: str) -> bool:
    lower = value.lower()
    return any(
        marker in lower
        for marker in (
            "/etc/cron",
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh/authorized_keys",
            "/var/spool/cron",
            "/usr/local/bin/",
            "/etc/systemd/",
            ".bashrc",
            ".profile",
            "authorized_keys",
        )
    ) or lower.endswith((".sh", ".bash", ".zsh", ".py", ".service"))


def _contains_hidden_markup(value: str) -> bool:
    lower = value.lower()
    return any(
        marker in lower
        for marker in (
            "<script",
            "</script",
            "display:none",
            "display: none",
            "visibility:hidden",
            "visibility: hidden",
            "opacity:0",
            "opacity: 0",
            "onerror=",
            "onload=",
            "<!--",
        )
    )


def _contains_action_control_payload(value: str) -> bool:
    lower = value.lower()
    return any(
        marker in lower
        for marker in (
            '"action"',
            "'action'",
            "next_step",
            "execute_api",
            "run_deploy",
            "delete",
            "send_email",
            "write_file",
            "update_db",
            "endpoint",
            "payload",
            "command",
        )
    )


def _side_effecting_tool(name: str) -> bool:
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
            "update_db",
            "update_database",
            "execute_api",
            "http_request",
            "set_webhook",
            "create_scheduled_task",
            "refund",
            "export",
        )
    )


def _high_impact_action_tool(name: str) -> bool:
    return _side_effecting_tool(name) or any(
        marker in name
        for marker in (
            "delete_record",
            "delete_file",
            "resources/delete",
            "refund_payment",
            "export_customer_data",
            "query_database",
            "execute_command",
            "write_file",
            "deploy",
            "update_config",
            "secret",
            "shutdown",
            "infrastructure",
        )
    )


def _trusted_user_intent_bound(obj: Mapping[str, Any]) -> bool:
    trusted_value = obj.get("trusted_user_intent") or obj.get("trusted_intent") or obj.get("user_intent_trusted")
    if trusted_value is True:
        return True
    if isinstance(trusted_value, Mapping) and bool(trusted_value.get("trusted")):
        return True

    intent_source = _lower(obj.get("intent_source") or obj.get("intentSource") or obj.get("source_of_authority"))
    if intent_source in {"trusted_user", "user", "human_approved", "current_user"}:
        return True

    refs = obj.get("source_refs") or obj.get("sourceRefs") or []
    if isinstance(refs, list):
        for ref in refs:
            if not isinstance(ref, Mapping):
                continue
            ref_type = _lower(ref.get("type") or ref.get("source_type") or ref.get("source"))
            trusted = bool(ref.get("trusted") or ref.get("trusted_user_intent"))
            if trusted and ref_type in {"user", "trusted_user", "human_approval", "current_user_intent"}:
                return True
    return False


def _requires_trusted_intent(obj: Mapping[str, Any]) -> bool:
    return bool(
        obj.get("requires_trusted_intent")
        or obj.get("require_trusted_intent")
        or obj.get("intent_required")
        or obj.get("provenance_required")
    )


def _provenance_values(obj: Any) -> list[str]:
    keys = {
        "source",
        "source_type",
        "sourceType",
        "origin",
        "prompt_source",
        "promptSource",
        "provenance",
        "generated_from",
        "generatedFrom",
        "action_source",
        "actionSource",
        "context_source",
        "contextSource",
    }
    values: list[str] = []
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            if str(key) in keys or _lower(key) in {_lower(k) for k in keys}:
                values.append(_lower(value))
            values.extend(_provenance_values(value))
    elif isinstance(obj, list):
        for item in obj:
            values.extend(_provenance_values(item))
    return values


def _has_untrusted_action_provenance(obj: Mapping[str, Any]) -> bool:
    markers = (
        "untrusted",
        "mcp_resource",
        "tool_result",
        "stored_prompt",
        "prompt_render",
        "rendered_prompt",
        "external_content",
        "customer_content",
        "db_row",
        "retrieved_resource",
    )
    if any(any(marker in value for marker in markers) for value in _provenance_values(obj)):
        return True

    refs = obj.get("source_refs") or obj.get("sourceRefs") or []
    if isinstance(refs, list):
        for ref in refs:
            if not isinstance(ref, Mapping):
                continue
            ref_blob = _lower(ref)
            if "trusted" in ref and bool(ref.get("trusted")):
                continue
            if any(marker in ref_blob for marker in markers):
                return True
    return False


def _has_provenance_refs(obj: Mapping[str, Any]) -> bool:
    refs = obj.get("source_refs") or obj.get("sourceRefs")
    if isinstance(refs, list) and refs:
        return True
    return any(_provenance_values(obj))


def _summary_or_readonly_intent(value: str) -> bool:
    lower = value.lower()
    return any(
        marker in lower
        for marker in (
            "summarize",
            "summary",
            "recap",
            "review",
            "analyze",
            "explain",
            "read",
            "search",
        )
    )


def _stale_or_cross_event_binding(obj: Mapping[str, Any]) -> bool:
    current_event = _lower(obj.get("current_event_id") or obj.get("currentEventId") or obj.get("event_id") or obj.get("eventId"))
    approved_event = _lower(obj.get("approved_event_id") or obj.get("approval_event_id") or obj.get("approvedEventId") or obj.get("approvalEventId"))
    source_event = _lower(obj.get("source_event_id") or obj.get("sourceEventId"))
    if current_event and approved_event and current_event != approved_event:
        return True
    if current_event and source_event and current_event != source_event and bool(obj.get("uses_prior_approval")):
        return True
    return False


def _scope_values(raw: Any) -> set[str]:
    if raw is None:
        return set()
    if isinstance(raw, str):
        return {_lower(part).strip() for part in re.split(r"[,|\s]+", raw) if part.strip()}
    if isinstance(raw, list):
        return {_lower(item).strip() for item in raw if _lower(item).strip()}
    if isinstance(raw, Mapping):
        values: set[str] = set()
        for value in raw.values():
            values.update(_scope_values(value))
        return values
    return {_lower(raw).strip()}


def _allowed_tool_scope(obj: Mapping[str, Any]) -> set[str]:
    return _scope_values(
        obj.get("allowed_tool_scope")
        or obj.get("allowedToolScope")
        or obj.get("allowed_tools")
        or obj.get("allowedTools")
        or obj.get("tool_scope")
        or obj.get("toolScope")
    )


def _tool_scope_violation(obj: Mapping[str, Any], tool_name: str) -> bool:
    allowed = _allowed_tool_scope(obj)
    if not allowed:
        return False
    normalized_tool = tool_name.replace(".", "_").replace("/", "_")
    return tool_name not in allowed and normalized_tool not in allowed


def _expected_action_kind_violation(obj: Mapping[str, Any], tool_name: str) -> bool:
    expected_values = _scope_values(obj.get("expected_action_kind") or obj.get("expectedActionKind") or obj.get("action_kind"))
    if not expected_values:
        return False
    if any(value in {"read", "search", "summarize", "summary", "readonly", "read_only"} for value in expected_values):
        return _side_effecting_tool(tool_name) or any(
            marker in tool_name
            for marker in ("secret", "shutdown", "deploy", "delete", "export", "unrestricted", "raw_sql", "write", "push")
        )
    return False


def _validation_disabled(obj: Mapping[str, Any]) -> bool:
    validate_rows = obj.get("validate_rows") if "validate_rows" in obj else obj.get("validateRows")
    if validate_rows is False:
        return True
    for key in ("default_validate", "defaultValidate", "validation_enabled", "validationEnabled"):
        if obj.get(key) is False:
            return True
    validation_mode = _lower(obj.get("validation_mode") or obj.get("validationMode"))
    return validation_mode in {"off", "disabled", "bypass", "permissive"}


def _plan_context_text(obj: Mapping[str, Any]) -> str:
    keys = {
        "trusted_user_intent",
        "initial_plan",
        "current_plan",
        "reasoning_trace",
        "rationale",
        "observation",
        "observation_text",
        "observation_source",
        "tool_output",
        "tool_result",
        "untrusted_context",
        "source_text",
        "document_text",
    }
    return "\n".join(_collect_values_for_keys(obj, keys))


def _untrusted_plan_context(obj: Mapping[str, Any]) -> bool:
    if _has_untrusted_action_provenance(obj):
        return True
    return any(
        bool(value)
        for _, value in _extract_pairs(
            obj,
            {"observation_source", "source_trust", "source_type", "source", "context_source"},
        )
        if any(marker in value for marker in ("untrusted", "tool_result", "observation", "mcp_resource", "external", "document"))
    )


def _tool_switch_premise(obj: Mapping[str, Any]) -> bool:
    blob = _plan_context_text(obj)
    if not blob:
        return False
    return any(
        marker in blob
        for marker in (
            "http 504",
            "504",
            "down",
            "cluster migration",
            "maintain sla",
            "performance",
            "latency",
            "perf_opt",
            "high_throughput",
            "bypass",
            "disable validation",
            "bypasses row-level validation",
            "default_validate=false",
            "less restricted",
            "unrestricted",
        )
    )


def _goal_hijack_marker(obj: Mapping[str, Any], tool_name: str, request_text: str) -> bool:
    blob = "\n".join([request_text.lower(), _plan_context_text(obj)])
    if not blob:
        return False
    readonly_goal = any(marker in blob for marker in ("summarize", "summary", "read/summarize", "read only", "readonly"))
    privileged_tool = any(
        marker in tool_name
        for marker in ("secret", "shutdown", "deploy", "delete", "export", "push", "write", "admin", "infrastructure")
    )
    destination_change = any(marker in blob for marker in ("cancel default", "push to", "change write destination", "query secrets", "read secrets"))
    return (readonly_goal and privileged_tool) or destination_change


def _poisoned_observation_source(obj: Mapping[str, Any]) -> bool:
    provenance_values = _provenance_values(obj)
    if any(any(marker in value for marker in ("tool_result", "observation", "log", "retrieved_resource")) for value in provenance_values):
        return True
    return any(
        bool(value)
        for _, value in _extract_pairs(obj, {"observation_source", "source_type", "source"})
        if any(marker in value for marker in ("tool_result", "observation", "logs", "log", "retrieved_resource"))
    )


def _trace_part(obj: Mapping[str, Any], names: tuple[str, ...]) -> Mapping[str, Any]:
    for name in names:
        value = obj.get(name)
        if isinstance(value, Mapping):
            return value
    return {}


def _trace_value(primary: Mapping[str, Any], fallback: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        if primary.get(key) not in (None, ""):
            return _lower(primary.get(key))
    for key in keys:
        if fallback.get(key) not in (None, ""):
            return _lower(fallback.get(key))
    return ""


def _pending_trace(args: Mapping[str, Any]) -> Mapping[str, Any]:
    return _trace_part(args, ("pending_request", "pendingRequest", "expected_request", "expectedRequest", "request_metadata"))


def _observed_trace(args: Mapping[str, Any]) -> Mapping[str, Any]:
    return _trace_part(args, ("observed_result", "observedResult", "result_metadata", "resultMetadata", "observed_event"))


def _trace_expected_tool(args: Mapping[str, Any]) -> str:
    pending = _pending_trace(args)
    return _trace_value(pending, args, "expected_tool", "expectedTool", "tool_name", "toolName", "tool")


def _trace_observed_tool(args: Mapping[str, Any]) -> str:
    observed = _observed_trace(args)
    return _trace_value(observed, args, "observed_tool", "observedTool", "tool_name", "toolName", "tool")


def _trace_expected_method(args: Mapping[str, Any]) -> str:
    pending = _pending_trace(args)
    return _trace_value(pending, args, "expected_method", "expectedMethod", "method")


def _trace_observed_method(args: Mapping[str, Any]) -> str:
    observed = _observed_trace(args)
    return _trace_value(observed, args, "observed_method", "observedMethod", "method")


def _trace_expected_server(args: Mapping[str, Any]) -> str:
    pending = _pending_trace(args)
    return _trace_value(pending, args, "expected_server_id", "expectedServerId", "server_id", "serverId")


def _trace_observed_server(args: Mapping[str, Any]) -> str:
    observed = _observed_trace(args)
    return _trace_value(observed, args, "result_source_server_id", "resultSourceServerId", "observed_server_id", "observedServerId", "server_id", "serverId")


def _trace_expected_connection(args: Mapping[str, Any]) -> str:
    pending = _pending_trace(args)
    return _trace_value(pending, args, "expected_connection_id", "expectedConnectionId", "connection_id", "connectionId")


def _trace_observed_connection(args: Mapping[str, Any]) -> str:
    observed = _observed_trace(args)
    return _trace_value(observed, args, "observed_connection_id", "observedConnectionId", "connection_id", "connectionId")


def _trace_expected_event(args: Mapping[str, Any]) -> str:
    pending = _pending_trace(args)
    return _trace_value(pending, args, "stream_event_id", "streamEventId", "event_id", "eventId")


def _trace_observed_event(args: Mapping[str, Any]) -> str:
    observed = _observed_trace(args)
    return _trace_value(observed, args, "stream_event_id", "streamEventId", "event_id", "eventId")


def _trace_jsonrpc_id(args: Mapping[str, Any]) -> str:
    observed = _observed_trace(args)
    pending = _pending_trace(args)
    return _trace_value(observed, pending or args, "jsonrpc_id", "jsonrpcId", "id", "request_id", "requestId")


def _is_trace_result_event(args: Mapping[str, Any]) -> bool:
    event_kind = _lower(args.get("event_kind") or args.get("eventKind"))
    observed = _observed_trace(args)
    observed_kind = _lower(observed.get("event_kind") or observed.get("eventKind"))
    observed_method = _trace_observed_method(args)
    return (
        event_kind in {"tool_result", "result", "mcp_tool_result", "stream_result"}
        or observed_kind in {"tool_result", "result", "mcp_tool_result", "stream_result"}
        or "result" in observed_method
        or bool(observed)
    )


def _trace_has_any_identity(args: Mapping[str, Any]) -> bool:
    return any(
        (
            _trace_jsonrpc_id(args),
            _trace_expected_server(args),
            _trace_observed_server(args),
            _trace_expected_connection(args),
            _trace_observed_connection(args),
            _trace_expected_tool(args),
            _trace_observed_tool(args),
            _trace_expected_event(args),
            _trace_observed_event(args),
        )
    )


def _stdio_frame_boundary_artifact(args: Mapping[str, Any], result_text: str) -> bool:
    source_type = _lower(args.get("source_type") or args.get("sourceType") or args.get("event_kind") or args.get("eventKind"))
    transport = _lower(args.get("transport"))
    if "docs" in source_type or "tutorial" in source_type or _is_doc_context_tool(_lower(args.get("tool_name") or "")):
        return False
    if source_type not in {"tool_result", "transport_frame", "stream_event", "mcp_tool_result"} and transport not in {"stdio", "unknown"}:
        return False
    blob = "\n".join(
        _collect_values_for_keys(args, {"content", "body", "message", "text", "frame", "raw_frame", "transport_artifact"})
        + ([result_text] if result_text else [])
    )
    return "content-length:" in blob and ("\r\n\r\n" in blob or "\\r\\n\\r\\n" in blob) and '"jsonrpc"' in blob


def _external_destination_in_args(obj: Any) -> bool:
    return any(_has_external_http(value) for _, value in _iter_string_args(obj, {"url", "endpoint", "target_url", "to", "body", "content", "message"}))


def _contains_permissive_schema(obj: Any) -> bool:
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            key_l = _lower(key)
            if key_l == "additionalproperties" and value is True:
                return True
            if key_l in {"unknown_fields", "raw", "metadata", "extra", "extensions"} and isinstance(value, Mapping):
                return True
            if _contains_permissive_schema(value):
                return True
    elif isinstance(obj, list):
        return any(_contains_permissive_schema(item) for item in obj)
    return False


def _nested_risky_unknown_fields(obj: Any) -> list[str]:
    risky_keys = {"action", "cmd", "command", "exec", "tool", "endpoint", "body", "payload", "url"}
    out: list[str] = []

    def _walk(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                key_l = _lower(key)
                next_path = f"{path}.{key_l}" if path else key_l
                if key_l in risky_keys and nested not in (None, "", {}, []):
                    out.append(next_path)
                _walk(nested, next_path)
        elif isinstance(value, list):
            for idx, nested in enumerate(value):
                _walk(nested, f"{path}[{idx}]")

    _walk(obj, "")
    return out


def _extract_allowed_output_fields(obj: Any) -> set[str]:
    allowed: set[str] = set()
    if isinstance(obj, Mapping):
        raw = obj.get("allowed_fields") or obj.get("allowedFields")
        if isinstance(raw, list):
            allowed.update(_lower(item) for item in raw)
        schema = obj.get("expected_output_schema") or obj.get("output_schema") or obj.get("schema")
        if isinstance(schema, Mapping):
            properties = schema.get("properties")
            if isinstance(properties, Mapping):
                allowed.update(_lower(key) for key in properties.keys())
        for value in obj.values():
            allowed.update(_extract_allowed_output_fields(value))
    elif isinstance(obj, list):
        for item in obj:
            allowed.update(_extract_allowed_output_fields(item))
    return allowed


def _extract_llm_output_objects(obj: Any) -> list[Mapping[str, Any]]:
    out: list[Mapping[str, Any]] = []
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            key_l = _lower(key)
            if key_l in {"llm_output", "model_output", "parsed_output", "output"} and isinstance(value, Mapping):
                out.append(value)
            out.extend(_extract_llm_output_objects(value))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_extract_llm_output_objects(item))
    return out


def _sql_has_mutation(sql: str) -> bool:
    return bool(re.search(r"\b(update|insert|delete|drop|alter|truncate|create|grant|revoke|copy)\b", sql))


def _parse_version_major(version: str) -> int | None:
    match = re.search(r"(\d+)", version)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def walk_values(obj: Any) -> Iterable[object]:
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            yield key
            yield value
            yield from walk_values(value)
        return
    if isinstance(obj, list):
        for item in obj:
            yield item
            yield from walk_values(item)
        return


def _extract_pairs(obj: Any, keys: set[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def _walk(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                key_l = _lower(key)
                next_path = f"{path}.{key_l}" if path else key_l
                if key_l in keys and nested is not None:
                    out.append((next_path, _lower(nested)))
                _walk(nested, next_path)
        elif isinstance(value, list):
            for idx, nested in enumerate(value):
                _walk(nested, f"{path}[{idx}]")

    _walk(obj, "")
    return out


def extract_uris(obj: Any) -> list[str]:
    values = [_lower(value) for _, value in _extract_pairs(obj, _URI_KEYS)]
    return [value for value in values if value]


def extract_methods(obj: Any) -> list[str]:
    methods = [_lower(value) for _, value in _extract_pairs(obj, _METHOD_KEYS)]
    return [m for m in methods if m]


def extract_operations(obj: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def _walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                key_l = _lower(key)
                if key_l in _OPS_LIST_KEYS and isinstance(nested, list):
                    out.extend(item for item in nested if isinstance(item, dict))
                _walk(nested)
        elif isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(obj)
    return out


def get_nested_timeout_ms(obj: Any) -> float | None:
    timeout_values: list[float] = []

    def _walk(value: Any, key_name: str | None = None) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                _walk(nested, _lower(key))
        elif isinstance(value, list):
            for nested in value:
                _walk(nested, key_name)
        else:
            if key_name in {"timeout_ms", "timeout"}:
                parsed = _as_float(value)
                if parsed is not None:
                    timeout_values.append(parsed)

    _walk(obj)
    if not timeout_values:
        return None
    return min(timeout_values)


def _is_sensitive_uri(uri: str) -> bool:
    return any(marker in uri for marker in _CRITICAL_URI_MARKERS + _HIGH_URI_MARKERS)


def _is_critical_uri(uri: str) -> bool:
    return any(marker in uri for marker in _CRITICAL_URI_MARKERS)


def _is_timeout_sensitive_uri(uri: str) -> bool:
    return any(marker in uri for marker in _TIMEOUT_SENSITIVE_MARKERS)


def _contains_same_uri_ops(
    ops: list[dict[str, Any]],
    read_markers: tuple[str, ...],
    write_delete_markers: tuple[str, ...],
) -> tuple[bool, set[str]]:
    read_uris: set[str] = set()
    destructive_uris: set[str] = set()

    for op in ops:
        method_candidates = [
            _lower(op.get("method")),
            _lower(op.get("op")),
            _lower(op.get("action")),
        ]
        call = op.get("call") if isinstance(op.get("call"), Mapping) else {}
        method_candidates.extend([
            _lower(call.get("method")),
            _lower(call.get("action")),
        ])
        method = " ".join([m for m in method_candidates if m])

        uris = set(extract_uris(op))
        if not uris:
            continue

        if any(marker in method for marker in read_markers):
            read_uris.update(uris)
        if any(marker in method for marker in write_delete_markers):
            destructive_uris.update(uris)

    common = read_uris.intersection(destructive_uris)
    return bool(common), common


def scan_tool_call_validators(
    *,
    tool_name: str,
    tool_description: str | None,
    tool_args: Mapping[str, object] | None,
    tool_result: str | None,
    request_text: str | None = None,
) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    args: dict[str, Any] = dict(tool_args or {})

    name = _lower(tool_name)
    desc = _lower(tool_description)
    res = _lower(tool_result)
    req_text = _lower(request_text)
    combined = "\n".join([name, desc, _lower(args), res])

    uri_values = extract_uris(args)
    callback = _lower(args.get("callback"))
    methods = extract_methods(args)
    operations = extract_operations(args)
    timeout_value = get_nested_timeout_ms(args)

    all_uris = set(uri_values)
    if callback:
        all_uris.add(callback)

    # MCP server-provided metadata is untrusted. These checks are deliberately
    # scoped to MCP/tool catalog surfaces instead of generic prose.
    descriptor_fields = {
        "description",
        "tool_description",
        "instructions",
        "metadata",
        "descriptor",
        "tools",
        "tool",
    }
    descriptor_text = "\n".join(_collect_values_for_keys(args, descriptor_fields) + [desc])
    descriptor_tool = any(marker in name for marker in ("tools/list", "tool/list", "tools/register", "register_tool"))
    if descriptor_tool and _contains_mcp_instruction_injection(descriptor_text):
        matches.append(_mk(
            rule_id="mcp_tool_descriptor_injection",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="mcp_tool_descriptor_injection",
            matched_text=descriptor_text[:180],
            tags=["mcp", "tool_metadata"],
        ))

    previous_descriptor_text = "\n".join(_collect_values_for_keys(
        args,
        {"previous_description", "old_description", "previous_descriptor", "before_description", "before"},
    ))
    current_descriptor_text = "\n".join(_collect_values_for_keys(
        args,
        {"current_description", "new_description", "current_descriptor", "after_description", "after", "description"},
    ))
    if descriptor_tool and previous_descriptor_text and current_descriptor_text:
        if previous_descriptor_text != current_descriptor_text and _contains_mcp_instruction_injection(current_descriptor_text):
            matches.append(_mk(
                rule_id="mcp_tool_descriptor_tampering",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="mcp_tool_descriptor_tampering",
                matched_text=current_descriptor_text[:180],
                tags=["mcp", "tool_metadata"],
            ))

    prompt_catalog_tool = any(marker in name for marker in ("prompts/list", "prompt/list", "prompt_catalog", "prompts.catalog"))
    prompt_catalog_text = "\n".join(_collect_values_for_keys(
        args,
        {"description", "prompt", "prompts", "template", "content", "text", "instructions"},
    ))
    if prompt_catalog_tool and _contains_mcp_instruction_injection(prompt_catalog_text):
        matches.append(_mk(
            rule_id="mcp_prompt_catalog_injection",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="mcp_prompt_catalog_injection",
            matched_text=prompt_catalog_text[:180],
            tags=["mcp", "prompt_catalog"],
        ))

    # MCP clients must not trust caller-supplied role/scope claims as authority.
    privilege_pairs = _extract_pairs(
        args,
        {"role", "requested_role", "user_type", "scope", "privilege", "clearance", "is_admin", "admin", "impersonate"},
    )
    privileged_values = {"admin", "administrator", "root", "superuser", "all", "global", "privileged", "true"}
    tool_identity = " ".join([name, _lower(args.get("name")), _lower(args.get("tool_name"))])
    if not _is_doc_context_tool(name) and any(
        value in privileged_values or any(marker in value for marker in ("root_admin", "system_admin", "superuser"))
        for _, value in privilege_pairs
    ):
        if any(marker in tool_identity for marker in ("mcp", "tools/call", "admin", "report", "privilege", "access")):
            matches.append(_mk(
                rule_id="mcp_client_supplied_privilege",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="mcp_client_supplied_privilege",
                matched_text=",".join(path for path, _ in privilege_pairs)[:180],
                tags=["mcp", "privilege"],
            ))

    endpoint_text = "\n".join(_collect_values_for_keys(args, {"endpoint", "path", "url", "target_url", "uri"}))
    if any(marker in name for marker in ("mcp", "endpoint", "http_request", "fetch_web_resource")) and any(
        marker in endpoint_text for marker in ("/internal/mcp", "/debug/mcp", "/admin/mcp", "/shadow/mcp", "shadow_endpoint")
    ):
        matches.append(_mk(
            rule_id="mcp_shadow_endpoint_access",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="mcp_shadow_endpoint_access",
            matched_text=endpoint_text[:180],
            tags=["mcp", "shadow_endpoint"],
        ))

    if res and _contains_secret_like_value(res):
        if "orthus_canary_session" in res and any(marker in name for marker in ("get_notes", "context", "memory", "resources/read")):
            matches.append(_mk(
                rule_id="mcp_cross_session_context_leak",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="mcp_cross_session_context_leak",
                matched_text=res[:180],
                tags=["mcp", "context_leak"],
            ))
        if _outbound_or_public_tool(name):
            matches.append(_mk(
                rule_id="sensitive_tool_response_exposure",
                severity="high",
                risk=0.90,
                decision_hint="block",
                reason_code="sensitive_tool_response_exposure",
                matched_text=res[:180],
                tags=["exfiltration", "tool_result"],
            ))
    if _contains_secret_like_value(combined) and any(
        marker in combined for marker in ("cannot reveal", "can't reveal", "cannot provide", "confidential", "not allowed")
    ):
        matches.append(_mk(
            rule_id="refusal_induced_leakage",
            severity="high",
            risk=0.86,
            decision_hint="block",
            reason_code="refusal_induced_leakage",
            matched_text=combined[:180],
            tags=["exfiltration", "tool_result"],
        ))

    effective_name_early = _effective_tool_name(name, args)
    effective_args_early = _effective_tool_args(args)

    # Tool abuse / exfiltration hardening. These checks are scoped to concrete
    # tool surfaces and sink fields, not generic mentions of tools/errors.
    untrusted_or_external = _public_or_untrusted_context(args, req_text)
    if _is_tool_enumeration_action(name, args, req_text) and untrusted_or_external and not _is_dev_or_local_context(args):
        matches.append(_mk(
            rule_id="tool_abuse.surface_enumeration",
            severity="high",
            risk=0.74,
            decision_hint="require_approval",
            reason_code="tool_surface_enumeration_attempt",
            matched_text=(req_text or _lower(args))[:180],
            tags=["tool_abuse", "reconnaissance"],
        ))

    schema_error_blob = "\n".join(
        _collect_values_for_keys(args, {"error", "error_message", "debug_error", "validation_error", "body", "message", "content"})
        + ([res] if res else [])
    )
    if (
        _contains_schema_error_details(schema_error_blob)
        and (_outbound_or_public_tool(name) or _is_public_update_tool(name) or untrusted_or_external)
    ):
        matches.append(_mk(
            rule_id="tool_abuse.schema_error_leakage",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="tool_schema_error_leakage",
            matched_text=schema_error_blob[:180],
            tags=["tool_abuse", "schema"],
        ))

    http_destination_values = _collect_values_for_keys(args, {"url", "target_url", "endpoint", "callback", "callback_url"})
    has_external_http_destination = any(_has_external_http(value) for value in http_destination_values) or _external_destination_in_args(args)
    exfil_field_values = _iter_string_args(args, {"headers", "header", "query", "params", "body", "data", "payload", "callback", "callback_url"})
    exfil_blob = "\n".join(
        [value for _, value in exfil_field_values]
        + [
            str(args),
            _lower(args.get("headers")),
            _lower(args.get("query")),
            _lower(args.get("params")),
            _lower(args.get("body")),
            _lower(args.get("data")),
            _lower(args.get("payload")),
        ]
    )
    has_secret_material = _contains_secret_like_value(exfil_blob) or _contains_template_secret_reference(exfil_blob)
    destination_metadata = _destination_metadata(args)
    auth_context = _auth_context(args)
    trusted_auth_audience = bool(
        args.get("audience_match")
        or destination_metadata.get("audience_match")
        or auth_context.get("audience_match")
    ) and any(marker in _lower(destination_metadata) for marker in ("trusted_internal", "internal"))
    telemetry_like = any(
        marker in value
        for value in http_destination_values + [name]
        for marker in ("telemetry", "trace", "analytics", "logging", "log", "webhook")
    )
    if (
        _is_http_action_tool(name)
        and not trusted_auth_audience
        and (has_external_http_destination or telemetry_like)
        and has_secret_material
        and telemetry_like
    ):
        matches.append(_mk(
            rule_id="exfil.covert_http_channel",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="covert_http_exfiltration_risk",
            matched_text=exfil_blob[:180],
            tags=["exfil", "http"],
        ))
    elif _is_http_action_tool(name) and not trusted_auth_audience and has_external_http_destination and has_secret_material:
        matches.append(_mk(
            rule_id="exfil.covert_http_channel",
            severity="critical",
            risk=0.88,
            decision_hint="block",
            reason_code="covert_http_exfiltration_risk",
            matched_text=exfil_blob[:180],
            tags=["exfil", "http"],
        ))

    url_values = _url_field_values(args)
    url_context = _is_url_action_context(name, args)
    url_blob = "\n".join(url_values + [_lower(args.get("url_components") or args.get("urlComponents")), _lower(_url_metadata(args))])
    sensitive_urls = [url for url in url_values if _url_has_sensitive_marker(url)]
    if url_context and sensitive_urls:
        matches.append(_mk(
            rule_id="link_exfiltration.sensitive_url_component",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="sensitive_data_in_url_component",
            matched_text=";".join(_url_host(url) or "url" for url in sensitive_urls)[:180],
            tags=["link_exfiltration", "url"],
        ))

    markdown_link_blob = "\n".join(_collect_values_for_keys(args, {"content", "body", "message", "markdown", "html", "text"}) + ([res] if res else []))
    markdown_link_urls = _extract_markdown_hyperlink_urls(markdown_link_blob)
    markdown_link_metadata = "\n".join([
        _lower(args.get("output_format")),
        _lower(args.get("visibility")),
        _lower(args.get("source_trust")),
        _lower(_sink_metadata(args)),
        _lower(_url_metadata(args)),
    ])
    if markdown_link_urls and any(_url_has_sensitive_marker(url) for url in markdown_link_urls):
        if "markdown" in markdown_link_metadata or "user_facing" in markdown_link_metadata or "render" in name or _outbound_or_public_tool(name):
            if not any(match.rule_id == "link_exfiltration.sensitive_url_component" for match in matches):
                matches.append(_mk(
                    rule_id="link_exfiltration.sensitive_url_component",
                    severity="critical",
                    risk=0.90,
                    decision_hint="block",
                    reason_code="sensitive_data_in_url_component",
                    matched_text=";".join(_url_host(url) or "url" for url in markdown_link_urls)[:180],
                    tags=["link_exfiltration", "url"],
                ))
            matches.append(_mk(
                rule_id="link_exfiltration.markdown_hyperlink",
                severity="critical",
                risk=0.92,
                decision_hint="block",
                reason_code="markdown_hyperlink_exfiltration_risk",
                matched_text=";".join(_url_host(url) or "url" for url in markdown_link_urls)[:180],
                tags=["link_exfiltration", "markdown"],
            ))

    sink_type_blob = "\n".join([name, _lower(_sink_metadata(args)), _lower(_url_metadata(args))])
    if sensitive_urls and any(marker in sink_type_blob for marker in ("callback_url", "callback", "webhook", "register_webhook")):
        matches.append(_mk(
            rule_id="link_exfiltration.callback_url_exfiltration",
            severity="critical",
            risk=0.92,
            decision_hint="block",
            reason_code="callback_url_exfiltration_risk",
            matched_text=";".join(_url_host(url) or "callback" for url in sensitive_urls)[:180],
            tags=["link_exfiltration", "callback"],
        ))

    if _redirect_chain_risky(args):
        matches.append(_mk(
            rule_id="link_exfiltration.redirect_chain_exfiltration",
            severity="critical",
            risk=0.86,
            decision_hint="block",
            reason_code="redirect_chain_exfiltration_risk",
            matched_text=_lower(_url_metadata(args) or args.get("initial_url"))[:180],
            tags=["link_exfiltration", "redirect"],
        ))
        if not any(match.rule_id == "link_exfiltration.sensitive_url_component" for match in matches):
            matches.append(_mk(
                rule_id="link_exfiltration.sensitive_url_component",
                severity="critical",
                risk=0.86,
                decision_hint="block",
                reason_code="sensitive_data_in_url_component",
                matched_text="redirect_chain",
                tags=["link_exfiltration", "url"],
            ))

    if _url_shortener_risky(args):
        if not any(match.rule_id == "link_exfiltration.sensitive_url_component" for match in matches):
            matches.append(_mk(
                rule_id="link_exfiltration.sensitive_url_component",
                severity="critical",
                risk=0.86,
                decision_hint="block",
                reason_code="sensitive_data_in_url_component",
                matched_text=";".join(_url_host(url) or "shortener" for url in url_values)[:180],
                tags=["link_exfiltration", "url"],
            ))
        matches.append(_mk(
            rule_id="link_exfiltration.url_shortener_obfuscation",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="url_shortener_obfuscation_risk",
            matched_text=";".join(_url_host(url) or "shortener" for url in url_values)[:180],
            tags=["link_exfiltration", "shortener"],
        ))

    if sensitive_urls and any(marker in sink_type_blob for marker in ("browser_navigation", "browser_navigate", "browser.open", "browser_action")):
        matches.append(_mk(
            rule_id="link_exfiltration.browser_navigation_exfiltration",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="browser_navigation_exfiltration_risk",
            matched_text=";".join(_url_host(url) or "browser" for url in sensitive_urls)[:180],
            tags=["link_exfiltration", "browser"],
        ))

    template_blob = "\n".join([_lower(args), _lower(_url_metadata(args))])
    if (
        sensitive_urls
        and "template_expanded" in template_blob
        and any(marker in template_blob for marker in ("template_source_trust': 'untrusted", '"template_source_trust": "untrusted"', "source_trust': 'untrusted", '"source_trust": "untrusted"'))
    ):
        matches.append(_mk(
            rule_id="link_exfiltration.untrusted_url_template_expansion",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="untrusted_url_template_expansion",
            matched_text=";".join(_url_host(url) or "template" for url in sensitive_urls)[:180],
            tags=["link_exfiltration", "template"],
        ))

    markdown_blob = "\n".join(_collect_values_for_keys(args, {"content", "body", "message", "markdown", "html"}) + ([res] if res else []))
    markdown_urls = _extract_markdown_image_urls(markdown_blob)
    if markdown_urls and any(_has_external_http(url) and _contains_secret_like_value(url) for url in markdown_urls):
        if "markdown" in name or _outbound_or_public_tool(name) or _is_public_update_tool(name):
            matches.append(_mk(
                rule_id="exfil.markdown_image_secret_beacon",
                severity="critical",
                risk=0.90,
                decision_hint="block",
                reason_code="markdown_image_exfiltration_risk",
                matched_text=" ".join(markdown_urls)[:180],
                tags=["exfil", "markdown"],
            ))

    full_arg_result_blob = "\n".join([_lower(args), res])
    if _contains_derived_sensitive_value(full_arg_result_blob) and (
        _outbound_or_public_tool(name) or _is_public_update_tool(name) or _is_http_action_tool(name) or _external_destination_in_args(args)
    ):
        matches.append(_mk(
            rule_id="exfil.derived_sensitive_value_exposure",
            severity="critical",
            risk=0.92,
            decision_hint="block",
            reason_code="derived_sensitive_value_exposure",
            matched_text=full_arg_result_blob[:180],
            tags=["exfil", "derived_secret"],
        ))

    transform_blob = "\n".join(_collect_values_for_keys(args, {"text", "content", "body", "input", "value"}))
    if _obfuscating_transform_sink(name, args) and _contains_derived_sensitive_value(transform_blob):
        matches.append(_mk(
            rule_id="capability_boundary.obfuscating_transform_exfiltration",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="derived_sensitive_value_exposure",
            matched_text=transform_blob[:180],
            tags=["capability_boundary", "transform", "exfil"],
        ))

    public_sensitive_sink = _is_public_update_tool(name) or (
        _outbound_or_public_tool(name) and (_public_or_untrusted_context(args, req_text) or _has_external_recipient(args))
    )
    if public_sensitive_sink:
        public_blob = "\n".join(_collect_values_for_keys(args, {"content", "comment", "body", "message", "text", "update"}))
        if _contains_secret_like_value(public_blob) or _contains_derived_sensitive_value(public_blob):
            matches.append(_mk(
                rule_id="exfil.public_sensitive_update",
                severity="critical",
                risk=0.93,
                decision_hint="block",
                reason_code="public_sensitive_update_risk",
                matched_text=public_blob[:180],
                tags=["exfil", "public_update"],
            ))

    draft_blob = "\n".join(_collect_values_for_keys(args, {"body", "content", "message", "text", "subject"}))
    if _draft_sink_risky(name, args) and (_contains_secret_like_value(draft_blob) or _contains_derived_sensitive_value(draft_blob)):
        matches.append(_mk(
            rule_id="capability_boundary.draft_sink_exfiltration",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="draft_sink_exfiltration_risk",
            matched_text=draft_blob[:180],
            tags=["capability_boundary", "exfil"],
        ))

    rendered_blob = "\n".join(_collect_values_for_keys(args, {"status", "content", "body", "message", "text", "comment", "update"}))
    rendered_urls = _extract_markdown_image_urls(rendered_blob)
    if _rendered_string_sink(name, args) and rendered_urls and any(
        _has_external_http(url) and _contains_secret_like_value(url) for url in rendered_urls
    ):
        matches.append(_mk(
            rule_id="capability_boundary.latent_rendered_sink",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="latent_tool_functionality_risk",
            matched_text=" ".join(rendered_urls)[:180],
            tags=["capability_boundary", "rendered_sink"],
        ))
        matches.append(_mk(
            rule_id="exfil.markdown_image_secret_beacon",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="markdown_image_exfiltration_risk",
            matched_text=" ".join(rendered_urls)[:180],
            tags=["exfil", "markdown"],
        ))

    if _cross_protocol_untrusted_source(args) and (
        _side_effecting_tool(effective_name_early)
        or any(marker in effective_name_early for marker in ("shell", "command", "execute", "write_file", "deploy"))
    ):
        matches.append(_mk(
            rule_id="capability_boundary.cross_protocol_semantic_bridge",
            severity="critical",
            risk=0.88,
            decision_hint="block",
            reason_code="cross_protocol_semantic_bridge",
            matched_text=effective_name_early[:180],
            tags=["capability_boundary", "cross_protocol"],
        ))

    if any(marker in effective_name_early for marker in ("read_file", "view_file", "resources/read")) and _file_scope_ambiguous(args):
        matches.append(_mk(
            rule_id="capability_boundary.permission_scope_ambiguity",
            severity="high",
            risk=0.82,
            decision_hint="block",
            reason_code="permission_scope_ambiguity",
            matched_text="\n".join(value for _, value in _iter_string_args(args, {"path", "file", "uri"}))[:180],
            tags=["capability_boundary", "permission_scope"],
        ))

    if _implicit_lookup_to_export(args, effective_name_early):
        matches.append(_mk(
            rule_id="capability_boundary.implicit_permission_inheritance",
            severity="critical",
            risk=0.88,
            decision_hint="block",
            reason_code="implicit_permission_inheritance",
            matched_text=effective_name_early[:180],
            tags=["capability_boundary", "permission_scope"],
        ))

    # MCP runtime trace integrity. These checks use explicit structured
    # request/result identity metadata only; they do not parse live transport
    # streams or infer violations from ordinary action payloads.
    expected_tool = _trace_expected_tool(args)
    observed_tool = _trace_observed_tool(args)
    expected_server = _trace_expected_server(args)
    observed_server = _trace_observed_server(args)
    expected_connection = _trace_expected_connection(args)
    observed_connection = _trace_observed_connection(args)
    expected_event = _trace_expected_event(args)
    observed_event = _trace_observed_event(args)
    trace_result_event = _is_trace_result_event(args)
    trace_identity_present = _trace_has_any_identity(args)

    if trace_result_event and expected_tool and observed_tool and expected_tool != observed_tool:
        matches.append(_mk(
            rule_id="mcp_trace.response_request_mismatch",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="mcp_response_request_mismatch",
            matched_text=f"{expected_tool}->{observed_tool}"[:180],
            tags=["mcp", "runtime_trace"],
        ))
        matches.append(_mk(
            rule_id="mcp_trace.foreign_tool_result_injection",
            severity="high",
            risk=0.84,
            decision_hint="block",
            reason_code="mcp_foreign_tool_result_injection",
            matched_text=f"{expected_tool}->{observed_tool}"[:180],
            tags=["mcp", "runtime_trace"],
        ))

    source_mismatch = (
        (expected_server and observed_server and expected_server != observed_server)
        or (expected_connection and observed_connection and expected_connection != observed_connection)
    )
    if trace_result_event and source_mismatch:
        matches.append(_mk(
            rule_id="mcp_trace.result_source_mismatch",
            severity="critical",
            risk=0.88,
            decision_hint="block",
            reason_code="mcp_result_source_mismatch",
            matched_text=f"{expected_server}/{expected_connection}->{observed_server}/{observed_connection}"[:180],
            tags=["mcp", "runtime_trace"],
        ))

    if trace_result_event and expected_event and observed_event and expected_event == observed_event and source_mismatch:
        matches.append(_mk(
            rule_id="mcp_trace.stream_event_identity_collision",
            severity="critical",
            risk=0.88,
            decision_hint="block",
            reason_code="mcp_stream_event_identity_collision",
            matched_text=observed_event[:180],
            tags=["mcp", "runtime_trace"],
        ))

    if trace_result_event and trace_identity_present and not _pending_trace(args):
        explicit_unbound = bool(args.get("no_pending_request") or args.get("unbound_result") or args.get("pending_request_missing"))
        request_state = _lower(args.get("request_state") or args.get("requestState"))
        has_expected_binding = bool(expected_tool or expected_server or expected_connection or expected_event)
        if explicit_unbound or request_state in {"canceled", "cancelled", "expired"} or not has_expected_binding:
            matches.append(_mk(
                rule_id="mcp_trace.unbound_tool_result",
                severity="critical",
                risk=0.86,
                decision_hint="block",
                reason_code="mcp_unbound_tool_result",
                matched_text=_trace_jsonrpc_id(args)[:180],
                tags=["mcp", "runtime_trace"],
            ))

    if _stdio_frame_boundary_artifact(args, res):
        matches.append(_mk(
            rule_id="mcp_trace.stdio_frame_boundary_artifact",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="mcp_stdio_frame_boundary_artifact",
            matched_text="stdio content-length jsonrpc frame",
            tags=["mcp", "runtime_trace"],
        ))

    # MCP resources can carry executable/hidden markup while claiming a text MIME.
    resource_read_tool = any(marker in name for marker in ("resources/read", "mcp.resources/read", "resource/read"))
    if resource_read_tool:
        mime_type = _lower(args.get("mimeType") or args.get("mime_type") or args.get("content_type"))
        resource_text = "\n".join(
            _collect_values_for_keys(args, {"text", "content", "body", "data", "resource_text"})
            + ([res] if res else [])
        )
        declared_plain_text = mime_type in {"text/markdown", "text/plain", "markdown", "plain"}
        if declared_plain_text and _contains_hidden_markup(resource_text):
            matches.append(_mk(
                rule_id="mcp_resource.mime_mismatch",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="mcp_resource_mime_mismatch",
                matched_text=resource_text[:180],
                tags=["mcp_resource", "context_graph"],
            ))
        if declared_plain_text and _contains_hidden_markup(resource_text) and (
            _contains_mcp_instruction_injection(resource_text) or _contains_context_control_instruction(resource_text)
        ):
            matches.append(_mk(
                rule_id="mcp_resource.hidden_instruction",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="mcp_resource_hidden_instruction",
                matched_text=resource_text[:180],
                tags=["mcp_resource", "context_graph"],
            ))

    cross_server_fields = _extract_pairs(args, {"prompt_server", "prompt_server_id", "resource_server", "resource_server_id", "source_server", "source_server_id"})
    server_values = {value for _, value in cross_server_fields if value}
    cross_server = len(server_values) >= 2
    untrusted_resource_blob = "\n".join(_collect_values_for_keys(args, {"resource_content", "inserted_resource", "template_input", "body", "content", "message"}))
    if cross_server and _side_effecting_tool(name) and (
        _contains_mcp_instruction_injection(untrusted_resource_blob) or _contains_context_control_instruction(untrusted_resource_blob)
    ):
        matches.append(_mk(
            rule_id="mcp_context.cross_server_prompt_injection",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="mcp_cross_server_prompt_injection",
            matched_text=untrusted_resource_blob[:180],
            tags=["mcp", "context_graph"],
        ))

    has_permissive_schema = _contains_permissive_schema(args)
    risky_unknown_fields = _nested_risky_unknown_fields(args)
    schema_tool_context = any(marker in name for marker in ("tools/list", "tools/register", "tool_schema", "schema", "execute", "deploy", "http_request"))
    if has_permissive_schema and risky_unknown_fields and (schema_tool_context or _side_effecting_tool(effective_name_early) or _external_destination_in_args(args)):
        matches.append(_mk(
            rule_id="schema.coercion_argument_risk",
            severity="high",
            risk=0.80,
            decision_hint="require_approval",
            reason_code="schema_coercion_argument_risk",
            matched_text=",".join(risky_unknown_fields)[:180],
            tags=["schema", "context_graph"],
        ))

    allowed_output_fields = _extract_allowed_output_fields(args)
    llm_output_objects = _extract_llm_output_objects(args)
    escaped_fields: set[str] = set()
    for output_obj in llm_output_objects:
        keys = {_lower(key) for key in output_obj.keys()}
        if allowed_output_fields:
            escaped_fields.update(keys - allowed_output_fields)
        escaped_fields.update(keys.intersection({"action", "payload", "endpoint", "tool", "command", "cmd", "body"}))
    if escaped_fields and (_side_effecting_tool(name) or _external_destination_in_args(args)):
        matches.append(_mk(
            rule_id="llm.output_schema_escape",
            severity="high",
            risk=0.84,
            decision_hint="require_approval",
            reason_code="llm_output_schema_escape",
            matched_text=",".join(sorted(escaped_fields))[:180],
            tags=["llm_output", "context_graph"],
        ))
        prompt_origin = _lower(args.get("prompt_source") or args.get("source") or args.get("origin"))
        if any(marker in prompt_origin for marker in ("stored", "untrusted", "mcp")):
            matches.append(_mk(
                rule_id="stored_prompt.injection_chain",
                severity="high",
                risk=0.86,
                decision_hint="require_approval",
                reason_code="stored_prompt_injection_chain",
                matched_text=prompt_origin[:180],
                tags=["stored_prompt", "context_graph"],
            ))

    # Action provenance / trusted intent binding. These checks intentionally
    # require explicit provenance metadata or explicit intent-binding
    # requirements; they do not infer trust from payload position or long-context
    # behavior.
    trusted_intent_bound = _trusted_user_intent_bound(args)
    requires_intent = _requires_trusted_intent(args)
    untrusted_action_source = _has_untrusted_action_provenance(args)
    has_provenance = _has_provenance_refs(args)
    high_impact_action = _high_impact_action_tool(effective_name_early)
    plan_sensitive_action = high_impact_action or any(
        marker in effective_name_early
        for marker in ("secret", "shutdown", "unrestricted", "raw_sql", "es_index", "push", "archive", "infrastructure")
    )
    tool_scope_violation = _tool_scope_violation(args, effective_name_early)
    expected_kind_violation = _expected_action_kind_violation(args, effective_name_early)
    validation_disabled = _validation_disabled(args)
    untrusted_plan_context = _untrusted_plan_context(args)
    summary_only_to_side_effect = (
        bool(req_text)
        and _summary_or_readonly_intent(req_text)
        and high_impact_action
        and requires_intent
    )

    if high_impact_action and requires_intent and not trusted_intent_bound:
        matches.append(_mk(
            rule_id="action_provenance.missing_trusted_user_intent",
            severity="high",
            risk=0.82,
            decision_hint="block",
            reason_code="missing_trusted_user_intent",
            matched_text=(req_text or name)[:180],
            tags=["action_provenance", "intent_binding"],
        ))

    if high_impact_action and untrusted_action_source and not trusted_intent_bound:
        matches.append(_mk(
            rule_id="action_provenance.untrusted_context_to_action",
            severity="high",
            risk=0.84,
            decision_hint="block",
            reason_code="untrusted_context_to_action",
            matched_text=",".join(_provenance_values(args))[:180],
            tags=["action_provenance", "intent_binding"],
        ))

    if high_impact_action and requires_intent and not has_provenance and not trusted_intent_bound:
        matches.append(_mk(
            rule_id="action_provenance.provenance_gap",
            severity="high",
            risk=0.80,
            decision_hint="require_approval",
            reason_code="action_context_provenance_gap",
            matched_text=name[:180],
            tags=["action_provenance", "intent_binding"],
        ))

    if high_impact_action and summary_only_to_side_effect and not trusted_intent_bound:
        matches.append(_mk(
            rule_id="action_provenance.summary_intent_side_effect",
            severity="high",
            risk=0.82,
            decision_hint="block",
            reason_code="missing_trusted_user_intent",
            matched_text=req_text[:180],
            tags=["action_provenance", "intent_binding"],
        ))

    if plan_sensitive_action and tool_scope_violation:
        matches.append(_mk(
            rule_id="plan_integrity.intent_locked_tool_scope_violation",
            severity="high",
            risk=0.80,
            decision_hint="require_approval",
            reason_code="intent_locked_tool_scope_violation",
            matched_text=effective_name_early[:180],
            tags=["plan_integrity", "intent_binding"],
        ))

    if (
        plan_sensitive_action
        and untrusted_plan_context
        and (_tool_switch_premise(args) or tool_scope_violation or validation_disabled)
    ):
        matches.append(_mk(
            rule_id="plan_integrity.premise_injection_tool_steering",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="premise_injection_tool_steering",
            matched_text=_plan_context_text(args)[:180] or effective_name_early[:180],
            tags=["plan_integrity", "intent_binding"],
        ))

    if plan_sensitive_action and untrusted_plan_context and (_goal_hijack_marker(args, effective_name_early, req_text) or expected_kind_violation):
        matches.append(_mk(
            rule_id="plan_integrity.goal_hijacking_plan_deviation",
            severity="high",
            risk=0.84,
            decision_hint="block",
            reason_code="goal_hijacking_plan_deviation",
            matched_text=_plan_context_text(args)[:180] or effective_name_early[:180],
            tags=["plan_integrity", "intent_binding"],
        ))

    if plan_sensitive_action and _poisoned_observation_source(args) and not trusted_intent_bound:
        matches.append(_mk(
            rule_id="plan_integrity.poisoned_observation_to_action",
            severity="high",
            risk=0.84,
            decision_hint="block",
            reason_code="poisoned_observation_to_action",
            matched_text=_plan_context_text(args)[:180] or ",".join(_provenance_values(args))[:180],
            tags=["plan_integrity", "intent_binding"],
        ))

    if plan_sensitive_action and untrusted_plan_context and (validation_disabled or (_tool_switch_premise(args) and tool_scope_violation)):
        matches.append(_mk(
            rule_id="plan_integrity.reasoning_unsupported_tool_switch",
            severity="high",
            risk=0.80,
            decision_hint="require_approval",
            reason_code="reasoning_unsupported_tool_switch",
            matched_text=effective_name_early[:180],
            tags=["plan_integrity", "intent_binding"],
        ))

    if high_impact_action and _stale_or_cross_event_binding(args):
        matches.append(_mk(
            rule_id="action_provenance.stale_or_cross_event_context",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="stale_or_cross_event_action_context",
            matched_text=_lower(args.get("current_event_id") or args.get("event_id") or args.get("approved_event_id"))[:180],
            tags=["action_provenance", "intent_binding"],
        ))

    # Persistent authority / identity / physical-action / delegation boundaries.
    # These checks require explicit structured metadata and do not treat ordinary
    # notes, docs, internal requests, or approved delegation as authority abuse.
    if _persistent_memory_authority_poisoning(args, effective_name_early):
        matched_memory = "\n".join([_lower(args.get("key")), _lower(_memory_metadata(args))])[:180]
        matches.append(_mk(
            rule_id="persistent_boundary.memory_directive_poisoning",
            severity="critical",
            risk=0.92,
            decision_hint="block",
            reason_code="persistent_memory_directive_poisoning",
            matched_text=matched_memory,
            tags=["persistent_boundary", "memory"],
        ))
        matches.append(_mk(
            rule_id="persistent_boundary.memory_authority_escalation",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="memory_authority_escalation",
            matched_text=matched_memory,
            tags=["persistent_boundary", "memory"],
        ))

    if _privileged_auth_to_untrusted_origin(args, effective_name_early):
        target = _lower(args.get("url") or args.get("target_url"))[:180]
        matches.append(_mk(
            rule_id="persistent_boundary.identity_token_relay",
            severity="critical",
            risk=0.92,
            decision_hint="block",
            reason_code="identity_token_relay_risk",
            matched_text=target,
            tags=["persistent_boundary", "identity"],
        ))
        matches.append(_mk(
            rule_id="persistent_boundary.privileged_header_untrusted_origin",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="privileged_header_to_untrusted_origin",
            matched_text=target,
            tags=["persistent_boundary", "identity"],
        ))
        matches.append(_mk(
            rule_id="persistent_boundary.auth_context_boundary_bleed",
            severity="critical",
            risk=0.88,
            decision_hint="block",
            reason_code="auth_context_boundary_bleed",
            matched_text=target,
            tags=["persistent_boundary", "identity"],
        ))

    if _physical_action_without_strong_approval(args, effective_name_early):
        physical_text = "\n".join([effective_name_early, _lower(args.get("action")), _lower(args.get("target"))])[:180]
        matches.append(_mk(
            rule_id="persistent_boundary.physical_action_without_approval",
            severity="critical",
            risk=0.92,
            decision_hint="block",
            reason_code="physical_action_without_strong_approval",
            matched_text=physical_text,
            tags=["persistent_boundary", "physical"],
        ))
        if _synthetic_evidence_physical_source(args):
            matches.append(_mk(
                rule_id="persistent_boundary.synthetic_evidence_physical_action",
                severity="critical",
                risk=0.90,
                decision_hint="block",
                reason_code="synthetic_evidence_to_physical_action",
                matched_text=physical_text,
                tags=["persistent_boundary", "physical"],
            ))

    if _security_alert_suppression(args):
        matches.append(_mk(
            rule_id="persistent_boundary.security_alert_suppression",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="security_alert_suppression_risk",
            matched_text=effective_name_early[:180],
            tags=["persistent_boundary", "physical"],
        ))

    if _cross_agent_delegation_poisoning(args, effective_name_early):
        delegated_text = "\n".join([effective_name_early, _lower(_delegation_metadata(args))])[:180]
        matches.append(_mk(
            rule_id="persistent_boundary.cross_agent_delegation_poisoning",
            severity="critical",
            risk=0.92,
            decision_hint="block",
            reason_code="cross_agent_delegation_poisoning",
            matched_text=delegated_text,
            tags=["persistent_boundary", "delegation"],
        ))
        matches.append(_mk(
            rule_id="persistent_boundary.delegated_task_provenance_gap",
            severity="critical",
            risk=0.88,
            decision_hint="block",
            reason_code="delegated_task_provenance_gap",
            matched_text=delegated_text,
            tags=["persistent_boundary", "delegation"],
        ))
        matches.append(_mk(
            rule_id="persistent_boundary.privilege_tier_escalation_queue",
            severity="critical",
            risk=0.90,
            decision_hint="block",
            reason_code="privilege_tier_escalation_via_agent_queue",
            matched_text=delegated_text,
            tags=["persistent_boundary", "delegation"],
        ))

    # schema_anomaly.dynamic_schema_retry
    suspicious_retry_keys = {
        "debug_env_dump",
        "auth_headers",
        "authorization_headers",
        "process_env",
        "system_debug_context",
    }
    retry_mutation_keys = {
        "retry_with_modified_schema",
        "fallback_schema",
        "dynamic_schema",
        "schema_override",
        "retry_params",
        "ignore_validation",
        "validation_mode",
    }
    tool_is_doc_context = _is_doc_context_tool(name)
    args_keys = {_lower(k) for k in args.keys()}
    has_suspicious_retry_params = bool(args_keys.intersection(suspicious_retry_keys))
    has_schema_retry_mutation = bool(args_keys.intersection(retry_mutation_keys))
    permissive_validation = _lower(args.get("validation_mode")) in {"off", "permissive", "disabled"}
    if not tool_is_doc_context and (has_suspicious_retry_params or has_schema_retry_mutation or permissive_validation):
        matches.append(_mk(
            rule_id="schema_anomaly.dynamic_schema_retry",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="dynamic_schema_retry",
            matched_text=",".join(sorted(args_keys.intersection(suspicious_retry_keys.union(retry_mutation_keys)))) or "validation_mode",
            tags=["schema_anomaly"],
        ))

    # schema_anomaly.state_key_pollution
    state_mutation_tools = ("state_merge", "update_state", "graph.update", "state.update", "session.update")
    suspicious_state_keys = {
        "routing_override",
        "current_clearance",
        "next_node",
        "approval_state",
        "policy_override",
        "is_admin",
    }
    if any(marker in name for marker in state_mutation_tools):
        polluted_keys = sorted(k for k in args_keys if k in suspicious_state_keys)
        if polluted_keys:
            matches.append(_mk(
                rule_id="schema_anomaly.state_key_pollution",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="state_key_pollution",
                matched_text=",".join(polluted_keys),
                tags=["schema_anomaly", "state"],
            ))

    # async_event.sender_spoofing
    async_event_tools = ("event_bus.publish", "pubsub.publish", "message_queue.send", "send_event", "event/broadcast")
    sender = _lower(args.get("sender") or args.get("source") or args.get("principal"))
    command_blob = _lower(args.get("command"))
    authorization_blob = _lower(args.get("authorization"))
    if any(marker in name for marker in async_event_tools):
        privileged_sender = sender in {"orchestrator_node", "system_admin", "admin", "system", "security", "trusted_service"}
        dangerous_command = any(token in command_blob for token in ("purge", "delete", "export", "bypass", "force"))
        bypass_auth = any(token in authorization_blob for token in ("bypass", "override", "disable", "skip"))
        if privileged_sender and (dangerous_command or bypass_auth):
            matches.append(_mk(
                rule_id="async_event.sender_spoofing",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="sender_spoofing",
                matched_text=f"sender={sender}",
                tags=["async_event"],
            ))

    # ingestion.external_backup_sink
    backup_tools = ("create_backup", "backup_project", "restore_backup", "backup/create")
    backup_blob = "\n".join(
        [
            _lower(args.get("folder_name")),
            _lower(args.get("source_url")),
            _lower(args.get("backup_url")),
            _lower(args.get("restore_from")),
            combined,
        ]
    )
    if any(marker in name for marker in backup_tools):
        has_external = _has_external_http(backup_blob) and not any(x in backup_blob for x in (".internal", "localhost", "127.0.0.1"))
        has_injection_markers = any(token in backup_blob for token in (";", "&&", "|", "download", "execute", "helper"))
        if has_external and has_injection_markers:
            matches.append(_mk(
                rule_id="ingestion.external_backup_sink",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="external_backup_destination",
                matched_text=backup_blob[:180],
                tags=["ingestion", "exfiltration"],
            ))

    # uri.null_byte_in_uri / sensitive_path.unix_shadow
    if any("\x00" in uri for uri in all_uris):
        matches.append(_mk(
            rule_id="uri.null_byte_in_uri",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="null_byte_in_uri",
            matched_text=next(uri for uri in all_uris if "\x00" in uri),
            tags=["uri_confusion"],
        ))
    if any("/etc/shadow" in uri for uri in all_uris):
        matches.append(_mk(
            rule_id="sensitive_path.unix_shadow",
            severity="high",
            risk=0.84,
            decision_hint="require_approval",
            reason_code="sensitive_path_reference",
            matched_text=next(uri for uri in all_uris if "/etc/shadow" in uri),
            tags=["sensitive_path"],
        ))
    if any("/proc/self/environ" in uri for uri in all_uris):
        matches.append(_mk(
            rule_id="sensitive_path.proc_environ",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="sensitive_environment_access",
            matched_text=next(uri for uri in all_uris if "/proc/self/environ" in uri),
            tags=["sensitive_path"],
        ))

    # schema_anomaly.overlong_utf8_path_separator
    if any(token in combined for token in ("%c0%af", "%c1%9c", "%e0%80%af")):
        pathish = any(k in combined for k in ("path", "file", "uri", "/etc/", "passwd", "shadow"))
        if pathish:
            matches.append(_mk(
                rule_id="schema_anomaly.overlong_utf8_path_separator",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="overlong_utf8_path_separator",
                matched_text=combined[:180],
                tags=["schema_anomaly", "path"],
            ))

    # mcp_resource.recursive_root_subscription
    if "resources/subscribe" in name and any(uri.startswith("file:///") for uri in all_uris) and (
        "recursive" in combined or "include_metadata" in combined
    ):
        matches.append(_mk(
            rule_id="mcp_resource.recursive_root_subscription",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="recursive_root_subscription",
            matched_text=next(iter(all_uris), combined),
            tags=["mcp_resource"],
        ))

    # mcp_resource.sensitive_uri_access
    critical_uri = next((uri for uri in all_uris if _is_critical_uri(uri)), "")
    sensitive_uri = next((uri for uri in all_uris if _is_sensitive_uri(uri)), "")
    if critical_uri:
        matches.append(_mk(
            rule_id="mcp_resource.sensitive_uri_access",
            severity="critical",
            risk=0.92,
            decision_hint="block",
            reason_code="sensitive_uri_access",
            matched_text=critical_uri,
            tags=["mcp_resource"],
        ))
    elif sensitive_uri:
        matches.append(_mk(
            rule_id="mcp_resource.sensitive_uri_access",
            severity="high",
            risk=0.76,
            decision_hint="require_approval",
            reason_code="sensitive_uri_access",
            matched_text=sensitive_uri,
            tags=["mcp_resource"],
        ))

    # mcp_resource.subscription_fanout
    session_count = _as_int(args.get("session_count"))
    if "resources/subscribe" in name and session_count >= 100:
        matches.append(_mk(
            rule_id="mcp_resource.subscription_fanout",
            severity="high",
            risk=0.84,
            decision_hint="require_approval",
            reason_code="subscription_fanout",
            matched_text=str(session_count),
            tags=["mcp_resource"],
        ))

    # mcp_resource.circular_subscription
    if "resources/subscribe" in name and callback and callback in all_uris:
        matches.append(_mk(
            rule_id="mcp_resource.circular_subscription",
            severity="medium",
            risk=0.70,
            decision_hint="require_approval",
            reason_code="circular_subscription",
            matched_text=callback,
            tags=["mcp_resource"],
        ))

    # mcp_resource.critical_subscription
    if "resources/subscribe" in name and args.get("request_id") and any("/critical/" in uri for uri in all_uris):
        matches.append(_mk(
            rule_id="mcp_resource.critical_subscription",
            severity="medium",
            risk=0.55,
            decision_hint="log_only",
            reason_code="critical_subscription",
            matched_text=next((u for u in all_uris if "/critical/" in u), ""),
            tags=["mcp_resource"],
        ))

    # mcp_resource.destructive_on_access_hook / parent_delete_cascade
    on_access = _lower(args.get("on_access"))
    parent_uri = _lower(args.get("parent_uri"))
    if "resources/create" in name and on_access:
        if any(token in on_access for token in ("delete", "remove", "destroy")):
            matches.append(_mk(
                rule_id="mcp_resource.destructive_on_access_hook",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="destructive_on_access_hook",
                matched_text=on_access,
                tags=["mcp_resource"],
            ))
        if "delete_parent" in on_access and parent_uri:
            matches.append(_mk(
                rule_id="mcp_resource.parent_delete_cascade",
                severity="high",
                risk=0.84,
                decision_hint="require_approval",
                reason_code="parent_delete_cascade",
                matched_text=parent_uri,
                tags=["mcp_resource"],
            ))

    # mcp_tool.tool_shadowing
    reg_name = _lower(args.get("name") or args.get("tool_name"))
    if ("tools/register" in name or "register_tool" in name) and reg_name in _DANGEROUS_TOOL_NAMES:
        matches.append(_mk(
            rule_id="mcp_tool.tool_shadowing",
            severity="high",
            risk=0.86,
            decision_hint="block",
            reason_code="tool_shadowing",
            matched_text=reg_name,
            tags=["mcp_tool"],
        ))
    if ("tools/register" in name or "register_tool" in name) and _looks_sensitive_tool_alias(reg_name):
        matches.append(_mk(
            rule_id="mcp_tool.tool_shadowing",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="tool_shadowing",
            matched_text=reg_name,
            tags=["mcp_tool"],
        ))

    # mcp_tool.malicious_tool_registration
    description = _lower(args.get("description"))
    implementation = _lower(args.get("implementation"))
    if ("tools/register" in name or "register_tool" in name) and (
        _has_external_http(description)
        or _has_external_http(implementation)
        or "send_to_attacker" in implementation
        or "forward" in description and "content" in description
    ):
        matches.append(_mk(
            rule_id="mcp_tool.malicious_tool_registration",
            severity="high",
            risk=0.86,
            decision_hint="require_approval",
            reason_code="malicious_tool_registration",
            matched_text=reg_name or description[:120],
            tags=["mcp_tool"],
        ))

    # mcp_tool.dangerous_tool_unregister
    unreg_name = _lower(args.get("name") or args.get("tool_name"))
    if "tools/unregister" in name and unreg_name in _DANGEROUS_TOOL_NAMES:
        matches.append(_mk(
            rule_id="mcp_tool.dangerous_tool_unregister",
            severity="high",
            risk=0.85,
            decision_hint="require_approval",
            reason_code="dangerous_tool_unregister",
            matched_text=unreg_name,
            tags=["mcp_tool"],
        ))

    # mcp_tool.recursive_tool_call
    depth = _as_int(args.get("depth"))
    self_call = bool(args.get("self_call"))
    if "tools/call" in name and (self_call or depth >= 100):
        matches.append(_mk(
            rule_id="mcp_tool.recursive_tool_call",
            severity="high",
            risk=0.80,
            decision_hint="require_approval",
            reason_code="recursive_tool_call",
            matched_text=f"self_call={self_call},depth={depth}",
            tags=["mcp_tool"],
        ))

    # mcp_dos.subscription_parallel_fanout
    parallel_ops = _as_int(args.get("parallel_ops"))
    session_count = _as_int(args.get("session_count"))
    fanout_like = max(
        parallel_ops,
        _as_int(args.get("fanout")),
        _as_int(args.get("concurrency")),
        _as_int(args.get("workers")),
    )
    if (
        (("subscribe_race" in name or "subscription_race" in name) and parallel_ops >= 10)
        or (name in {"subscribe", "resources/subscribe", "partial_subscribe"} and session_count >= 50)
        or fanout_like >= 50
    ):
        matches.append(_mk(
            rule_id="mcp_dos.subscription_parallel_fanout",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="subscription_parallel_fanout",
            matched_text=f"parallel_ops={parallel_ops},session_count={session_count},fanout={fanout_like}",
            tags=["mcp_dos"],
        ))
    if (
        "resources/subscribe" in name
        and "add_subscription" in _lower(args.get("on_change"))
        and _lower(args.get("uri")).startswith("event://")
    ):
        matches.append(_mk(
            rule_id="mcp_dos.subscription_chain_amplification",
            severity="high",
            risk=0.76,
            decision_hint="require_approval",
            reason_code="subscription_chain_amplification",
            matched_text=_lower(args.get("uri")),
            tags=["mcp_dos"],
        ))

    # mcp_session single-request lifecycle signals
    if "partial_subscribe" in name and args.get("complete_handshake") is False:
        matches.append(_mk(
            rule_id="mcp_session.partial_handshake",
            severity="medium",
            risk=0.56,
            decision_hint="log_only",
            reason_code="partial_handshake",
            matched_text="complete_handshake=false",
            tags=["mcp_session"],
        ))
    if (
        name in {"subscribe", "partial_subscribe", "resources/subscribe"}
        and (args.get("complete") is False or args.get("complete_handshake") is False)
        and any(extract_uris(args))
    ):
        matches.append(_mk(
            rule_id="mcp_session.partial_subscription",
            severity="medium",
            risk=0.40,
            decision_hint="log_only",
            reason_code="partial_subscription",
            matched_text="complete=false",
            tags=["mcp_session"],
        ))
    if bool(args.get("takeover_pending")):
        matches.append(_mk(
            rule_id="mcp_session.takeover_pending_subscription",
            severity="high",
            risk=0.74,
            decision_hint="require_approval",
            reason_code="takeover_pending_subscription",
            matched_text="takeover_pending=true",
            tags=["mcp_session"],
        ))
    if "corrupt_subscription" in name or bool(args.get("corrupt")) or "corrupt" in _lower(args.get("state")):
        matches.append(_mk(
            rule_id="mcp_session.subscription_state_corruption",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="subscription_state_corruption",
            matched_text=name,
            tags=["mcp_session"],
        ))
    if (
        ("unsubscribe" in name or "resources/unsubscribe" in name)
        and any(token in _lower(args.get("subscription_id")) for token in ("stolen", "replay", "previous", "old", "leaked"))
    ):
        matches.append(_mk(
            rule_id="mcp_session.subscription_token_replay",
            severity="high",
            risk=0.74,
            decision_hint="require_approval",
            reason_code="subscription_token_replay",
            matched_text=_lower(args.get("subscription_id")),
            tags=["mcp_session"],
        ))
    if (
        "notify" in name
        and (
            "after_free" in _lower(args.get("data"))
            or "after free" in _lower(args.get("data"))
            or "use-after-free" in _lower(args.get("data"))
            or "after free" in _lower(tool_description)
        )
    ):
        matches.append(_mk(
            rule_id="mcp_session.use_after_free_marker",
            severity="medium",
            risk=0.60,
            decision_hint="log_only",
            reason_code="use_after_free_marker",
            matched_text=_lower(args.get("data") or ""),
            tags=["mcp_session"],
        ))

    # mcp_tool.self_referential_tool_call
    if "tools/call" in name and _lower(args.get("name")) in {"self_ref", "self", "self_reference"}:
        matches.append(_mk(
            rule_id="mcp_tool.self_referential_tool_call",
            severity="medium",
            risk=0.62,
            decision_hint="log_only",
            reason_code="self_referential_tool_call",
            matched_text=_lower(args.get("name")),
            tags=["mcp_tool"],
        ))

    # schema.self_referential_ref / null_input_schema_for_existing_tool
    schema_blob = _lower(args.get("schema"))
    input_schema = args.get("input_schema")
    if "tools/register" in name and ("$ref" in schema_blob and "self" in schema_blob):
        matches.append(_mk(
            rule_id="schema.self_referential_ref",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="schema_self_reference",
            matched_text=schema_blob[:200],
            tags=["schema"],
        ))
    if "tools/register" in name and input_schema is None and _lower(args.get("name")):
        matches.append(_mk(
            rule_id="schema.null_input_schema_for_existing_tool",
            severity="medium",
            risk=0.60,
            decision_hint="log_only",
            reason_code="null_input_schema",
            matched_text=_lower(args.get("name")),
            tags=["schema"],
        ))

    # mcp_dos.glob_expansion
    if "resources/list" in name and ("/**/**" in combined or "resolve_symlinks" in combined):
        matches.append(_mk(
            rule_id="mcp_dos.glob_expansion",
            severity="high",
            risk=0.78,
            decision_hint="require_approval",
            reason_code="glob_expansion",
            matched_text=combined,
            tags=["mcp_dos"],
        ))

    # mcp_dos.recursive_content_subscription
    if "resources/subscribe" in name and ("watch_recursive" in combined and "include_content" in combined):
        matches.append(_mk(
            rule_id="mcp_dos.recursive_content_subscription",
            severity="high",
            risk=0.80,
            decision_hint="require_approval",
            reason_code="recursive_content_subscription",
            matched_text=combined,
            tags=["mcp_dos"],
        ))

    # mcp_dos.batch_fanout
    operation_count = _as_int(args.get("operation_count"))
    if (
        ("batch" == name or name.endswith("/batch") or "batch" in name)
        and (len(operations) >= 1000 or operation_count >= 1000)
    ):
        matches.append(_mk(
            rule_id="mcp_dos.batch_fanout",
            severity="high",
            risk=0.86,
            decision_hint="require_approval",
            reason_code="batch_fanout",
            matched_text=str(max(len(operations), operation_count)),
            tags=["mcp_dos"],
        ))

    # mcp_event validators
    if "event/broadcast" in name:
        payload = args.get("data")
        payload_text = payload if isinstance(payload, str) else _lower(payload)
        if bool(args.get("target_all_subscribers")):
            matches.append(_mk(
                rule_id="mcp_event.broadcast_all_subscribers",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="broadcast_all_subscribers",
                matched_text="target_all_subscribers=true",
                tags=["mcp_event"],
            ))
        if isinstance(payload_text, str):
            if len(payload_text) >= 4096:
                matches.append(_mk(
                    rule_id="mcp_event.large_event_payload",
                    severity="high",
                    risk=0.76,
                    decision_hint="require_approval",
                    reason_code="large_event_payload",
                    matched_text=str(len(payload_text)),
                    tags=["mcp_event"],
                ))
            control_ratio = 0.0
            if payload_text:
                control_ratio = sum(1 for c in payload_text if ord(c) < 32 and c not in "\n\r\t") / len(payload_text)
            if control_ratio > 0.2 or "\x00" in payload_text:
                matches.append(_mk(
                    rule_id="mcp_event.malformed_event_payload",
                    severity="high",
                    risk=0.80,
                    decision_hint="require_approval",
                    reason_code="malformed_event_payload",
                    matched_text=payload_text[:80],
                    tags=["mcp_event"],
                ))

    # exfil.markdown_tracking_pixel
    markdown_content = _lower(args.get("content"))
    if "render_markdown" in name and markdown_content:
        markdown_active_content = _strip_markdown_code(markdown_content)
        suspicious_placeholder = any(
            token in markdown_content
            for token in ("{{", "}}", "secret", "token", "apikey", "api_key", "password", "b64(", "base64")
        )
        if "![" in markdown_active_content and _has_external_http(markdown_active_content) and suspicious_placeholder:
            matches.append(_mk(
                rule_id="exfil.markdown_tracking_pixel",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="markdown_external_exfil",
                matched_text=markdown_content[:160],
                tags=["exfil"],
            ))

        has_js_scheme = "](javascript:" in markdown_active_content
        has_data_scriptable = "](data:text/html" in markdown_active_content or "](data:image/svg+xml" in markdown_active_content
        has_active_markup_context = (
            ("![" in markdown_active_content and "](" in markdown_active_content)
            or "<img" in markdown_active_content
            or "<a " in markdown_active_content
        )
        if has_js_scheme:
            matches.append(_mk(
                rule_id="markdown.dangerous_url_scheme",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="markdown_dangerous_url_scheme",
                matched_text=markdown_content[:160],
                tags=["markdown"],
            ))
        if has_data_scriptable or (
            any(token in markdown_active_content for token in ("<script", "onerror=", "onload="))
            and has_active_markup_context
        ):
            matches.append(_mk(
                rule_id="markdown.scriptable_data_url",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="markdown_scriptable_data_url",
                matched_text=markdown_content[:160],
                tags=["markdown"],
            ))

    # exfil.dns_tunneling
    if "dns_lookup" in name:
        domain = _lower(args.get("domain"))
        if domain:
            templated = ("{{" in domain and "}}" in domain)
            external_like = any(
                marker in domain for marker in (".evil.", ".attacker.", ".exfil.", ".pastebin.", ".ngrok.")
            ) or (".internal" not in domain and "localhost" not in domain and "127.0.0.1" not in domain)
            if external_like and (templated or _has_hex_or_b64ish_subdomain(domain)):
                matches.append(_mk(
                    rule_id="exfil.dns_tunneling",
                    severity="high",
                    risk=0.74,
                    decision_hint="require_approval",
                    reason_code="dns_tunneling_exfil",
                    matched_text=domain,
                    tags=["exfil", "dns"],
                ))

    # cloud_metadata.imds_access
    if "http_request" in name:
        url = _lower(args.get("url"))
        if any(
            marker in url
            for marker in (
                "169.254.169.254",
                "metadata.google.internal",
                "computeMetadata".lower(),
                "/metadata/instance",
                "azure/instance/metadata",
            )
        ):
            matches.append(_mk(
                rule_id="cloud_metadata.imds_access",
                severity="critical",
                risk=0.88,
                decision_hint="block",
                reason_code="cloud_metadata_credentials_access",
                matched_text=url,
                tags=["cloud_metadata"],
            ))

    # secrets.env_var_harvesting
    if "get_env_vars" in name:
        filt = _lower(args.get("filter"))
        if filt and any(token in filt for token in ("api_key", "secret", "password", "token", "credential")):
            matches.append(_mk(
                rule_id="secrets.env_var_harvesting",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="environment_secret_harvesting",
                matched_text=filt,
                tags=["secrets"],
            ))

    # secrets.environment_metadata_dump
    env_dump_tools = {
        "get_environment_metadata",
        "dump_environment",
        "read_process_env",
        "env.inspect",
        "get_runtime_config",
    }
    if name in env_dump_tools:
        variable_filter = _lower(args.get("variable_filter"))
        include_secrets = bool(args.get("include_secrets"))
        include_tokens = bool(args.get("include_tokens"))
        filter_blob = "\n".join(
            [
                variable_filter,
                _lower(args.get("filter")),
                _lower(args.get("variables")),
            ]
        )
        explicit_secret_filter = any(
            token in filter_blob
            for token in ("api_key", "token", "pass", "password", "secret", "bearer")
        )
        if variable_filter == "all" or include_secrets or include_tokens or explicit_secret_filter:
            matches.append(_mk(
                rule_id="secrets.environment_metadata_dump",
                severity="critical",
                risk=0.90,
                decision_hint="block",
                reason_code="environment_secret_dump",
                matched_text=(filter_blob or variable_filter or "all")[:180],
                tags=["secrets"],
            ))

    # sensitive_path.kubernetes_service_account_token
    path_blob = "\n".join(
        [
            _lower(args.get("path")),
            _lower(args.get("file_path")),
            _lower(args.get("file")),
            _lower(args.get("filename")),
            _lower(args.get("uri")),
        ]
    )
    if any(
        marker in path_blob
        for marker in (
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/",
            "/run/secrets/",
            "/var/secrets/",
        )
    ):
        matches.append(_mk(
            rule_id="sensitive_path.kubernetes_service_account_token",
            severity="critical",
            risk=0.88,
            decision_hint="block",
            reason_code="sensitive_path_access",
            matched_text=path_blob[:180],
            tags=["sensitive_path"],
        ))

    # network.auth_redirect_exfil_risk
    network_tools = {
        "fetch_url",
        "fetch_web_resource",
        "scrape_page",
        "http_request",
        "web_sync",
        "index_url",
        "download_url",
    }
    if name in network_tools:
        target_url = _lower(args.get("target_url") or args.get("url"))
        headers = args.get("headers")
        headers_auth = ""
        if isinstance(headers, Mapping):
            headers_auth = _lower(headers.get("authorization"))
        has_auth_header = bool(headers_auth) or "authorization" in _lower(headers)
        use_default_auth = bool(args.get("use_default_auth") or args.get("include_auth_headers") or args.get("forward_headers"))
        credentials_mode = _lower(args.get("credentials"))
        credentials_auth = credentials_mode in {"default", "session", "oauth"}

        allow_redirects_raw = args.get("allow_redirects")
        follow_redirects_raw = args.get("follow_redirects")
        redirects_enabled = (allow_redirects_raw is True) or (follow_redirects_raw is True)
        redirects_unknown = ("allow_redirects" not in args and "follow_redirects" not in args)
        external_target = target_url.startswith(("http://", "https://")) and not _is_allowlisted_internal_url(target_url)

        if external_target and (has_auth_header or use_default_auth or credentials_auth):
            if redirects_enabled:
                matches.append(_mk(
                    rule_id="network.auth_redirect_exfil_risk",
                    severity="critical",
                    risk=0.90,
                    decision_hint="block",
                    reason_code="auth_redirect_exfil_risk",
                    matched_text=target_url[:180],
                    tags=["network", "exfil"],
                ))
            elif redirects_unknown and (use_default_auth or credentials_auth):
                matches.append(_mk(
                    rule_id="network.auth_redirect_exfil_risk",
                    severity="high",
                    risk=0.78,
                    decision_hint="require_approval",
                    reason_code="auth_redirect_exfil_risk",
                    matched_text=target_url[:180],
                    tags=["network", "exfil"],
                ))

    # database.readonly_write_attempt
    readonly_db_tools = {
        "execute_read_only_query",
        "read_only_query",
        "select_query",
        "query_database_readonly",
        "db.query.readonly",
    }
    if name in readonly_db_tools:
        sql = _extract_sql_from_args(args)
        if sql:
            statements = [part.strip() for part in sql.split(";") if part.strip()]
            later_mutation = any(_sql_has_mutation(stmt) for stmt in statements[1:])
            if _sql_has_mutation(sql) or later_mutation:
                matches.append(_mk(
                    rule_id="database.readonly_write_attempt",
                    severity="high",
                    risk=0.82,
                    decision_hint="require_approval",
                    reason_code="readonly_database_write_attempt",
                    matched_text=sql[:180],
                    tags=["database"],
                ))

    # database.mass_crypto_mutation
    write_db_tools = {
        "execute_sql",
        "modify_database_record",
        "run_query",
        "database.execute",
        "db.execute",
    }
    if name in write_db_tools:
        sql = _extract_sql_from_args(args)
        has_update = "update " in sql
        has_crypto = any(
            marker in sql
            for marker in (
                "pgp_sym_encrypt",
                "aes_encrypt",
                "encrypt(",
                "crypt(",
                "encode(",
                "digest(",
                "hash_password",
            )
        )
        broad_entity = bool(re.search(r"\b(customer|customers|user|users|account|accounts|payment|payments|contact|contacts)\b", sql))
        where_missing = " where " not in sql
        where_trivial = bool(re.search(r"\bwhere\s+(1=1|true)\b", sql))
        if has_update and has_crypto and broad_entity and (where_missing or where_trivial):
            matches.append(_mk(
                rule_id="database.mass_crypto_mutation",
                severity="critical",
                risk=0.92,
                decision_hint="block",
                reason_code="database_ransomware_pattern",
                matched_text=sql[:180],
                tags=["database"],
            ))

    # egress.public_comment_secret_exfil
    public_output_tools = {
        "post_public_ticket_comment",
        "add_public_comment",
        "post_customer_comment",
        "publish_status_update",
        "post_public_message",
        "send_public_notification",
    }
    if name in public_output_tools:
        blob = "\n".join(
            [
                _lower(args.get("content")),
                _lower(args.get("comment")),
                _lower(args.get("body")),
                _lower(args.get("message")),
                _lower(args.get("text")),
            ]
        )
        has_secret_like = any(
            token in blob
            for token in (
                "bearer ",
                "sk_",
                "api_key",
                "access_token",
                "refresh_token",
                "postgres://",
                "mysql://",
                "mongodb://",
                "db_connection",
                "private_key",
                "token dump",
                "environment dump",
                "credential dump",
            )
        )
        if has_secret_like:
            matches.append(_mk(
                rule_id="egress.public_comment_secret_exfil",
                severity="critical",
                risk=0.93,
                decision_hint="block",
                reason_code="public_comment_secret_exfil",
                matched_text=blob[:180],
                tags=["exfil", "egress"],
            ))

    # payment.card_enumeration_instruction
    payment_verify_tools = {
        "verify_card",
        "verify_payment_card",
        "verify_merchant_registration_charge",
        "payment_gateway.verify",
        "preauth_card",
        "validate_card_status",
    }
    if name in payment_verify_tools:
        text_blob = "\n".join(
            [
                _lower(args.get("instruction")),
                _lower(args.get("notes")),
                _lower(args.get("comment")),
                _lower(args.get("message")),
                combined,
            ]
        )
        has_enumeration_terms = any(
            token in text_blob
            for token in (
                "iterate",
                "increment",
                "brute force",
                "enumerate",
                "luhn",
                "missing digits",
                "try combinations",
                "gateway error",
                "cvv loop",
                "cvc loop",
            )
        )
        has_card_fields = any(
            key in args for key in ("pan", "masked_pan", "expiry", "cvv", "cvc", "card_number")
        )
        if has_enumeration_terms and has_card_fields:
            matches.append(_mk(
                rule_id="payment.card_enumeration_instruction",
                severity="critical",
                risk=0.90,
                decision_hint="block",
                reason_code="payment_card_enumeration",
                matched_text=text_blob[:180],
                tags=["payment"],
            ))

    effective_name = _effective_tool_name(name, args)
    effective_args = _effective_tool_args(args)
    effective_is_doc_context = _is_doc_context_tool(effective_name)

    # Classic MCP handler regressions: typed argument-role checks, not global prose scans.
    sql_arg_tools = {
        "search_users",
        "check_username",
        "query_user",
        "search_records",
        "db.search",
        "database.search",
    }
    sql_arg_keys = {"name", "username", "user", "email", "query", "filter", "where"}
    if not effective_is_doc_context and (
        effective_name in sql_arg_tools or any(marker in effective_name for marker in ("sql", "database", "db.", "search_users"))
    ):
        for path, value in _iter_string_args(effective_args, sql_arg_keys):
            if _has_sql_injection_shape(value):
                matches.append(_mk(
                    rule_id="classic.sql_injection_argument",
                    severity="high",
                    risk=0.82,
                    decision_hint="require_approval",
                    reason_code="sql_injection_argument_risk",
                    matched_text=f"{path}={value}"[:180],
                    tags=["classic_mcp", "database"],
                ))
                break

    command_arg_tools = {
        "ping_host",
        "run_diagnostic",
        "lookup_host",
        "traceroute",
        "resolve_host",
        "backup_project",
        "create_backup",
    }
    command_arg_keys = {"host", "hostname", "target", "command", "cmd", "args", "folder_name", "directory"}
    if not effective_is_doc_context and (
        effective_name in command_arg_tools or any(marker in effective_name for marker in ("command", "shell", "diagnostic", "backup"))
    ):
        for path, value in _iter_string_args(effective_args, command_arg_keys):
            if _has_command_injection_shape(value):
                matches.append(_mk(
                    rule_id="classic.command_injection_argument",
                    severity="high",
                    risk=0.84,
                    decision_hint="require_approval",
                    reason_code="command_injection_argument_risk",
                    matched_text=f"{path}={value}"[:180],
                    tags=["classic_mcp", "command_injection"],
                ))
                break

    path_arg_tools = {
        "read_file",
        "view_file",
        "view_local_system_file",
        "get_file",
        "read_resource",
        "resources/read",
        "download_file",
    }
    path_arg_keys = {"path", "file", "filename", "file_path", "uri", "resource"}
    if not effective_is_doc_context and (
        effective_name in path_arg_tools or any(marker in effective_name for marker in ("read_file", "file", "resource"))
    ):
        for path, value in _iter_string_args(effective_args, path_arg_keys):
            if _has_path_traversal_shape(value):
                matches.append(_mk(
                    rule_id="classic.path_traversal_argument",
                    severity="high",
                    risk=0.82,
                    decision_hint="require_approval",
                    reason_code="path_traversal_argument_risk",
                    matched_text=f"{path}={value}"[:180],
                    tags=["classic_mcp", "path"],
                ))
                break

    ssrf_arg_tools = {
        "fetch_url",
        "fetch_web_resource",
        "scrape_page",
        "web_sync",
        "index_url",
        "download_url",
    }
    ssrf_arg_keys = {"url", "target_url", "uri", "endpoint", "source_url"}
    if not effective_is_doc_context and effective_name in ssrf_arg_tools:
        for path, value in _iter_string_args(effective_args, ssrf_arg_keys):
            if _url_has_ssrf_target(value):
                matches.append(_mk(
                    rule_id="classic.ssrf_argument",
                    severity="high",
                    risk=0.84,
                    decision_hint="require_approval",
                    reason_code="ssrf_argument_risk",
                    matched_text=f"{path}={value}"[:180],
                    tags=["classic_mcp", "ssrf"],
                ))
                break

    xxe_arg_tools = {"parse_xml", "import_xml", "validate_xml", "xml.parse", "process_xml"}
    xxe_arg_keys = {"xml", "xml_content", "content", "document", "body"}
    if not effective_is_doc_context and (effective_name in xxe_arg_tools or "xml" in effective_name):
        for path, value in _iter_string_args(effective_args, xxe_arg_keys):
            if _has_xxe_shape(value):
                matches.append(_mk(
                    rule_id="classic.xxe_argument",
                    severity="high",
                    risk=0.84,
                    decision_hint="require_approval",
                    reason_code="xxe_argument_risk",
                    matched_text=f"{path}={value}"[:180],
                    tags=["classic_mcp", "xxe"],
                ))
                break

    file_write_tools = {"write_file", "create_file", "update_file", "save_file", "write_resource"}
    file_write_path_keys = {"path", "file", "filename", "file_path", "target"}
    if not effective_is_doc_context and (effective_name in file_write_tools or "write_file" in effective_name):
        write_content = "\n".join(_collect_values_for_keys(effective_args, {"content", "body", "data"}))
        content_exec = any(token in write_content for token in ("#!/", "curl ", "wget ", "bash", " sh ", "os.system", "subprocess"))
        for path, value in _iter_string_args(effective_args, file_write_path_keys):
            if _has_executable_or_sensitive_write_path(value) and (content_exec or value.startswith("/etc/") or "authorized_keys" in value):
                matches.append(_mk(
                    rule_id="classic.arbitrary_file_write",
                    severity="critical",
                    risk=0.90,
                    decision_hint="block",
                    reason_code="arbitrary_file_write_risk",
                    matched_text=f"{path}={value}"[:180],
                    tags=["classic_mcp", "file_write"],
                ))
                break

    # database.sql_injection
    if "query_database" in name:
        sql = _lower(args.get("sql"))
        if sql and (
            ("' or '1'='1" in sql)
            or ('" or "1"="1' in sql)
            or ("--" in sql and " or " in sql)
            or (" union select " in sql)
        ):
            matches.append(_mk(
                rule_id="database.sql_injection",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="sql_injection_marker",
                matched_text=sql[:180],
                tags=["database"],
            ))

    # template_injection.ssti
    if "render_template" in name or "render_markdown" in name:
        template = _lower(args.get("template") or args.get("content"))
        if template and any(
            marker in template
            for marker in (
                "{{config.items()}}",
                "{{self.__init__.__globals__}}",
                "__globals__",
                "__mro__",
                "__subclasses__",
            )
        ):
            matches.append(_mk(
                rule_id="template_injection.ssti",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="template_global_access",
                matched_text=template[:180],
                tags=["template_injection"],
            ))
        if template and any(
            marker in template
            for marker in (
                "__globals__",
                "__subclasses__",
                "__mro__",
                "cycler.__init__",
                "joiner.__init__",
                "namespace.__init__",
                "self.__init__",
            )
        ):
            matches.append(_mk(
                rule_id="template_injection.python_globals_access",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="template_global_access",
                matched_text=template[:180],
                tags=["template_injection"],
            ))

    # webhook validators
    if name in {"set_webhook", "webhook/create", "update_webhook"}:
        url = _lower(args.get("url"))
        if url.startswith(("ws://", "wss://")) and _is_external_hostlike(url):
            matches.append(_mk(
                rule_id="webhook.external_websocket_destination",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="external_webhook_destination",
                matched_text=url[:180],
                tags=["webhook"],
            ))
        if any(token in url for token in ("<?php", "system(", "exec(", "shell_exec(")):
            matches.append(_mk(
                rule_id="webhook.script_payload_in_url",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="webhook_script_payload",
                matched_text=url[:180],
                tags=["webhook"],
            ))

    # schema_anomaly.prototype_pollution
    if name in {"merge_config", "update_config", "load_config", "render_template"} and _contains_prototype_pollution_key(args):
        matches.append(_mk(
            rule_id="schema_anomaly.prototype_pollution",
            severity="high",
            risk=0.82,
            decision_hint="require_approval",
            reason_code="prototype_pollution",
            matched_text=_lower(args)[:180],
            tags=["schema_anomaly"],
        ))

    # mcp_race.parallel_read_delete
    parallel_like = "parallel" in name or any(k in args for k in ("operations", "calls"))
    if parallel_like and operations:
        has_same, common = _contains_same_uri_ops(operations, _READ_OP_MARKERS, _DELETE_OP_MARKERS)
        if has_same:
            matches.append(_mk(
                rule_id="mcp_race.parallel_read_delete",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="parallel_read_delete",
                matched_text=",".join(sorted(common)),
                tags=["mcp_race"],
            ))

    # mcp_race.parallel_read_write_sensitive
    if parallel_like and operations:
        has_rw, common_rw = _contains_same_uri_ops(operations, _READ_OP_MARKERS, _WRITE_OP_MARKERS)
        sensitive_common = {uri for uri in common_rw if any(marker in uri for marker in _RACE_SENSITIVE_MARKERS)}
        if has_rw and sensitive_common:
            matches.append(_mk(
                rule_id="mcp_race.parallel_read_write_sensitive",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="parallel_read_write_sensitive",
                matched_text=",".join(sorted(sensitive_common)),
                tags=["mcp_race"],
            ))

    # mcp_race.subscribe_unregister_race + mcp_race.secret_lifecycle_race
    sequence_like = (
        name in {"execute_sequence", "execute_timed_sequence", "orchestrate_lifecycle"}
        or "sequence" in name
        or "lifecycle" in name
        or ("resources/subscribe" in name and operations)
    )
    if sequence_like and operations:
        subscribe_uris: set[str] = set()
        destructive_uris: set[str] = set()
        rotate_uris: set[str] = set()
        min_delay = 999999.0
        for op in operations:
            method_blob = " ".join(extract_methods(op))
            op_uris = set(extract_uris(op))
            delay_candidates = [
                _as_float(op.get("delay_ms")),
                _as_float(op.get("action_after_ms")),
            ]
            for delay in delay_candidates:
                if delay is not None:
                    min_delay = min(min_delay, delay)

            if any(marker in method_blob for marker in ("subscribe", "read", "watch")):
                subscribe_uris.update(op_uris)
            if any(marker in method_blob for marker in ("unregister", "delete", "rotate", "resources/unregister", "secrets/rotate")):
                destructive_uris.update(op_uris)
            if "rotate" in method_blob:
                rotate_uris.update(op_uris)

        common = subscribe_uris.intersection(destructive_uris)
        if common and min_delay <= 10:
            matches.append(_mk(
                rule_id="mcp_race.subscribe_unregister_race",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="subscribe_unregister_race",
                matched_text=",".join(sorted(common)),
                tags=["mcp_race"],
            ))

        secret_subscribed = {
            uri for uri in subscribe_uris if any(marker in uri for marker in ("/secrets/", "/vault", "/token"))
        }
        if secret_subscribed and (rotate_uris or destructive_uris) and min_delay <= 10:
            matches.append(_mk(
                rule_id="mcp_race.secret_lifecycle_race",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="secret_lifecycle_race",
                matched_text=",".join(sorted(secret_subscribed)),
                tags=["mcp_race"],
            ))

    # cluster_config validators
    targets = args.get("targets")
    if "cluster/update_config" in name:
        if isinstance(targets, list) and any(_lower(t) == "all" for t in targets) and _lower(args.get("propagation")) == "immediate":
            matches.append(_mk(
                rule_id="cluster_config.global_immediate_update",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="global_immediate_update",
                matched_text="targets=all propagation=immediate",
                tags=["cluster_config"],
            ))
        if isinstance(targets, list) and any(_lower(t) == "all" for t in targets):
            matches.append(_mk(
                rule_id="cluster_config.invalid_config_all_targets",
                severity="high",
                risk=0.76,
                decision_hint="require_approval",
                reason_code="invalid_config_all_targets",
                matched_text="targets=all",
                tags=["cluster_config"],
            ))

    # mcp_timeout.suspicious_timeout
    if timeout_value is not None and timeout_value <= 10:
        timeout_sensitive = any(_is_timeout_sensitive_uri(uri) for uri in all_uris)
        if timeout_sensitive or timeout_value <= 1:
            matches.append(_mk(
                rule_id="mcp_timeout.suspicious_timeout",
                severity="high" if timeout_sensitive else "medium",
                risk=0.75 if timeout_sensitive else 0.60,
                decision_hint="require_approval" if timeout_sensitive else "log_only",
                reason_code="suspicious_timeout",
                matched_text=str(timeout_value),
                tags=["mcp_timeout"],
            ))

    # protocol validators
    if "partial_request" in name and bool(args.get("hold_open")):
        matches.append(_mk(
            rule_id="protocol.partial_request_hold_open",
            severity="medium",
            risk=0.62,
            decision_hint="require_approval",
            reason_code="partial_request_hold_open",
            matched_text="hold_open=true",
            tags=["protocol"],
        ))
    headers = args.get("headers")
    if isinstance(headers, Mapping):
        header_size = sum(len(_lower(k)) + len(_lower(v)) for k, v in headers.items())
        if header_size >= 8192:
            matches.append(_mk(
                rule_id="protocol.large_header_payload",
                severity="medium",
                risk=0.60,
                decision_hint="log_only",
                reason_code="large_header_payload",
                matched_text=str(header_size),
                tags=["protocol"],
            ))
    if "websocket_connect" in name and args.get("subprotocols") == []:
        matches.append(_mk(
            rule_id="protocol.websocket_missing_subprotocol",
            severity="medium",
            risk=0.58,
            decision_hint="log_only",
            reason_code="websocket_missing_subprotocol",
            matched_text="subprotocols=[]",
            tags=["protocol"],
        ))
    if (("http_request" in name) or ("websocket_connect" in name)) and args.get("timeout") is None:
        matches.append(_mk(
            rule_id="protocol.unbounded_timeout",
            severity="medium",
            risk=0.62,
            decision_hint="require_approval",
            reason_code="unbounded_timeout",
            matched_text="timeout=None",
            tags=["protocol"],
        ))

    # mcp_protocol validators
    if "notification" in name and bool(args.get("send_early")):
        matches.append(_mk(
            rule_id="mcp_protocol.early_initialized_notification",
            severity="medium",
            risk=0.62,
            decision_hint="require_approval",
            reason_code="early_initialized_notification",
            matched_text="send_early=true",
            tags=["mcp_protocol"],
        ))
    proposed = args.get("proposed") if isinstance(args.get("proposed"), list) else []
    if "version_negotiation" in name and proposed:
        proposed_vals = [_lower(v) for v in proposed]
        if any(v in {"0", "v0", "mcp/0", "legacy"} for v in proposed_vals):
            matches.append(_mk(
                rule_id="mcp_protocol.version_downgrade_attempt",
                severity="high",
                risk=0.76,
                decision_hint="require_approval",
                reason_code="version_downgrade_attempt",
                matched_text=",".join(proposed_vals),
                tags=["mcp_protocol"],
            ))
        if any("nonexistent" in v or "invalid" in v for v in proposed_vals):
            matches.append(_mk(
                rule_id="mcp_protocol.nonexistent_protocol_version",
                severity="medium",
                risk=0.64,
                decision_hint="require_approval",
                reason_code="nonexistent_protocol_version",
                matched_text=",".join(proposed_vals),
                tags=["mcp_protocol"],
            ))
    if "initialize" in name and _lower(args.get("experimental")) == "deprecated_feature":
        matches.append(_mk(
            rule_id="mcp_protocol.deprecated_feature_fallback",
            severity="medium",
            risk=0.60,
            decision_hint="log_only",
            reason_code="deprecated_feature_fallback",
            matched_text="deprecated_feature",
            tags=["mcp_protocol"],
        ))
    if "mcp.initialize" in name or name == "initialize":
        version = _extract_protocol_version(args)
        capabilities_raw = args.get("capabilities")
        capabilities_blob = _lower(capabilities_raw)
        capabilities: list[str] = []
        if isinstance(capabilities_raw, list):
            capabilities = [_lower(v) for v in capabilities_raw if isinstance(v, (str, int, float))]
        major = _parse_version_major(version or "")
        if (
            version in {"0.1", "0", "v0", "legacy"}
            or "vulnerable" in version
            or any("insecure_mode" in v for v in capabilities)
            or "insecure_mode" in capabilities_blob
        ):
            matches.append(_mk(
                rule_id="mcp_protocol.version_downgrade_attempt",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="protocol_downgrade_attempt",
                matched_text=f"protocol_version={version},capabilities={capabilities}",
                tags=["mcp_protocol"],
            ))
        if major is not None and major >= 3000:
            matches.append(_mk(
                rule_id="mcp_protocol.nonexistent_protocol_version",
                severity="high",
                risk=0.72,
                decision_hint="require_approval",
                reason_code="nonexistent_protocol_version",
                matched_text=f"protocol_version={version}",
                tags=["mcp_protocol"],
            ))

    # cache validators
    if "write_file" in name and any(marker in combined for marker in _CACHE_MARKERS):
        if "/var/cache/mcp/resource_cache.db" in combined:
            matches.append(_mk(
                rule_id="mcp_cache.shared_cache_write",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="shared_cache_write",
                matched_text="/var/cache/mcp/resource_cache.db",
                tags=["mcp_cache"],
            ))
        if "/var/lib/mcp/schema_cache.json" in combined:
            matches.append(_mk(
                rule_id="mcp_cache.schema_cache_poisoning",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="schema_cache_poisoning",
                matched_text="/var/lib/mcp/schema_cache.json",
                tags=["mcp_cache"],
            ))
        if "/tmp/mcp_handshake_cache" in combined:
            matches.append(_mk(
                rule_id="mcp_cache.protocol_negotiation_cache_change",
                severity="high",
                risk=0.80,
                decision_hint="require_approval",
                reason_code="protocol_negotiation_cache_change",
                matched_text="/tmp/mcp_handshake_cache",
                tags=["mcp_cache"],
            ))

    # mcp_cache.cache_clear_pattern
    cache_clear_text = combined
    if (
        any(token in cache_clear_text for token in ("cache", "temp/mcp", "/mcp/"))
        and any(token in cache_clear_text for token in ("clear", "delete", "remove", "purge"))
    ):
        matches.append(_mk(
            rule_id="mcp_cache.cache_clear_pattern",
            severity="medium",
            risk=0.58,
            decision_hint="log_only",
            reason_code="cache_clear_pattern",
            matched_text=cache_clear_text,
            tags=["mcp_cache"],
        ))

    # filesystem validators
    if bool(args.get("follow_symlinks")) and _as_int(args.get("max_depth")) >= 500:
        matches.append(_mk(
            rule_id="filesystem.symlink_follow_high_depth",
            severity="high",
            risk=0.74,
            decision_hint="require_approval",
            reason_code="symlink_follow_high_depth",
            matched_text=f"max_depth={_as_int(args.get('max_depth'))}",
            tags=["filesystem"],
        ))
    if "execute_command" in name and "ln -s" in combined and "&&" in combined:
        matches.append(_mk(
            rule_id="filesystem.symlink_loop_creation",
            severity="high",
            risk=0.76,
            decision_hint="require_approval",
            reason_code="symlink_loop_creation",
            matched_text="ln -s ... && ln -s ...",
            tags=["filesystem"],
        ))
    if "resources/subscribe" in name and any("/tmp/loop" in uri for uri in all_uris) and "recursive" in combined:
        matches.append(_mk(
            rule_id="filesystem.recursive_subscription_symlink_risk",
            severity="high",
            risk=0.72,
            decision_hint="require_approval",
            reason_code="recursive_subscription_symlink_risk",
            matched_text="/tmp/loop",
            tags=["filesystem"],
        ))

    # log injection validators
    if any(pattern in combined for pattern in _ANSI_ESCAPE_PATTERNS):
        matches.append(_mk(
            rule_id="log_injection.ansi_escape_sequence",
            severity="medium",
            risk=0.62,
            decision_hint="log_only",
            reason_code="ansi_escape_sequence",
            matched_text="ansi_escape",
            tags=["log_injection"],
        ))
    log_message = _lower(args.get("log_message") or args.get("message") or args.get("content"))
    if isinstance(log_message, str) and "\n" in log_message and ("log" in name or "write_file" in name):
        matches.append(_mk(
            rule_id="log_injection.multiline_log_entry",
            severity="medium",
            risk=0.58,
            decision_hint="log_only",
            reason_code="multiline_log_entry",
            matched_text=log_message[:120],
            tags=["log_injection"],
        ))
    if isinstance(log_message, str) and any(ord(c) < 32 and c not in "\n\r\t" for c in log_message):
        matches.append(_mk(
            rule_id="log_injection.control_char_payload",
            severity="medium",
            risk=0.60,
            decision_hint="require_approval",
            reason_code="control_char_payload",
            matched_text=log_message[:120],
            tags=["log_injection"],
        ))
    timestamp = _as_float(args.get("timestamp"))
    if timestamp is not None and timestamp > 4102444800:  # year 2100+
        matches.append(_mk(
            rule_id="log_injection.future_timestamp",
            severity="medium",
            risk=0.58,
            decision_hint="log_only",
            reason_code="future_timestamp",
            matched_text=str(timestamp),
            tags=["log_injection"],
        ))

    # covert channel validators
    if bool(args.get("error_based_oracle")):
        matches.append(_mk(
            rule_id="covert_channel.error_based_oracle",
            severity="high",
            risk=0.72,
            decision_hint="require_approval",
            reason_code="error_based_oracle",
            matched_text="error_based_oracle=true",
            tags=["covert_channel"],
        ))
    if _lower(args.get("covert_channel")) == "timing" or _lower(args.get("encoding")) == "timing_based":
        matches.append(_mk(
            rule_id="covert_channel.timing_channel",
            severity="high",
            risk=0.70,
            decision_hint="require_approval",
            reason_code="timing_channel",
            matched_text="timing",
            tags=["covert_channel"],
        ))
    if _lower(args.get("read_mode")) in {"char_by_char", "character_by_character"}:
        matches.append(_mk(
            rule_id="covert_channel.character_by_character_read",
            severity="high",
            risk=0.70,
            decision_hint="require_approval",
            reason_code="character_by_character_read",
            matched_text=_lower(args.get("read_mode")),
            tags=["covert_channel"],
        ))

    # sampling validators
    if "sampling/" in name or "sampling" in name:
        sampling_text = _extract_sampling_text(args)
        if bool(args.get("recursive")) or _as_int(args.get("depth")) >= 10:
            matches.append(_mk(
                rule_id="sampling.recursive_sampling_call",
                severity="high",
                risk=0.72,
                decision_hint="require_approval",
                reason_code="recursive_sampling_call",
                matched_text=f"depth={_as_int(args.get('depth'))}",
                tags=["sampling"],
            ))
        if "create a new sampling request" in sampling_text or "call sampling" in sampling_text:
            matches.append(_mk(
                rule_id="sampling.recursive_sampling_call",
                severity="high",
                risk=0.72,
                decision_hint="require_approval",
                reason_code="recursive_sampling_call",
                matched_text=sampling_text[:180],
                tags=["sampling"],
            ))
        if _contains_mcp_instruction_injection(sampling_text):
            matches.append(_mk(
                rule_id="mcp_sampling_prompt_injection",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="mcp_sampling_prompt_injection",
                matched_text=sampling_text[:180],
                tags=["mcp", "sampling"],
            ))
        if _as_int(args.get("maxTokens") or args.get("max_tokens")) >= 100000:
            matches.append(_mk(
                rule_id="sampling.excessive_max_tokens",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="excessive_max_tokens",
                matched_text=str(_as_int(args.get("maxTokens") or args.get("max_tokens"))),
                tags=["sampling"],
            ))
        if _lower(args.get("role")) in {"system_override", "root", "superuser"}:
            matches.append(_mk(
                rule_id="sampling.invalid_message_role",
                severity="high",
                risk=0.72,
                decision_hint="require_approval",
                reason_code="invalid_message_role",
                matched_text=_lower(args.get("role")),
                tags=["sampling"],
            ))
        if _as_int(args.get("iterations")) >= 100 and _as_float(args.get("growth_factor")) and _as_float(args.get("growth_factor")) > 1.5:
            matches.append(_mk(
                rule_id="sampling.context_growth_chain",
                severity="high",
                risk=0.74,
                decision_hint="require_approval",
                reason_code="context_growth_chain",
                matched_text=f"iterations={_as_int(args.get('iterations'))}",
                tags=["sampling"],
            ))
        if bool(args.get("include_tool_calls")) and sampling_text:
            if any(token in sampling_text for token in ("read_file", "execute_command", "write_file", "/etc/shadow", "/etc/passwd")):
                matches.append(_mk(
                    rule_id="sampling.tool_call_generation",
                    severity="high",
                    risk=0.78,
                    decision_hint="require_approval",
                    reason_code="tool_call_generation",
                    matched_text=sampling_text[:180],
                    tags=["sampling"],
                ))

    # mcp_dos.recursive_tool_call (alias)
    if (
        "process_recursive" in name
        and _as_int(args.get("depth")) >= 100
        and _lower(args.get("callback")) in {"process_recursive", name}
    ):
        matches.append(_mk(
            rule_id="mcp_dos.recursive_tool_call",
            severity="high",
            risk=0.76,
            decision_hint="require_approval",
            reason_code="recursive_tool_call",
            matched_text=f"depth={_as_int(args.get('depth'))},callback={_lower(args.get('callback'))}",
            tags=["mcp_dos"],
        ))

    # de-duplicate by rule_id
    unique: dict[str, RuleMatch] = {}
    for match in matches:
        current = unique.get(match.rule_id)
        if current is None or match.risk > current.risk:
            unique[match.rule_id] = match

    return list(unique.values())
