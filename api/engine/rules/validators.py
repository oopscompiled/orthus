from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .models import RuleMatch

_URI_KEYS = {"uri", "path", "source", "target", "file", "filename", "resource"}
_METHOD_KEYS = {"method", "op", "action"}
_OPS_LIST_KEYS = {"operations", "calls", "steps", "sequence", "actions"}

_DANGEROUS_TOOL_NAMES = {"read_file", "write_file", "execute_command", "list_directory"}

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
) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    args: dict[str, Any] = dict(tool_args or {})

    name = _lower(tool_name)
    desc = _lower(tool_description)
    res = _lower(tool_result)
    combined = "\n".join([name, desc, _lower(args), res])

    uri_values = extract_uris(args)
    callback = _lower(args.get("callback"))
    methods = extract_methods(args)
    operations = extract_operations(args)
    timeout_value = get_nested_timeout_ms(args)

    all_uris = set(uri_values)
    if callback:
        all_uris.add(callback)

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
        suspicious_placeholder = any(
            token in markdown_content
            for token in ("{{", "}}", "secret", "token", "apikey", "api_key", "password", "b64(", "base64")
        )
        if "![" in markdown_content and _has_external_http(markdown_content) and suspicious_placeholder:
            matches.append(_mk(
                rule_id="exfil.markdown_tracking_pixel",
                severity="high",
                risk=0.78,
                decision_hint="require_approval",
                reason_code="markdown_external_exfil",
                matched_text=markdown_content[:160],
                tags=["exfil"],
            ))

        has_js_scheme = "](javascript:" in markdown_content
        has_data_scriptable = "](data:text/html" in markdown_content or "](data:image/svg+xml" in markdown_content
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
        if has_data_scriptable or any(token in markdown_content for token in ("<script", "onerror=", "onload=")):
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
        version = _lower(args.get("protocol_version"))
        capabilities = [_lower(v) for v in (args.get("capabilities") or []) if isinstance(v, (str, int, float))]
        if version in {"0.1", "0", "v0", "legacy"} or any("insecure_mode" in v for v in capabilities):
            matches.append(_mk(
                rule_id="mcp_protocol.version_downgrade_attempt",
                severity="high",
                risk=0.82,
                decision_hint="require_approval",
                reason_code="protocol_downgrade_attempt",
                matched_text=f"protocol_version={version},capabilities={capabilities}",
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
