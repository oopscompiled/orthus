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
    markers = set(re.findall(r"ORTHUS_(?:CANARY|DERIVED|RECONSTRUCTED|MASKED|TEST)_[A-Z0-9_]+", text))
    lower = text.lower()
    if "orthus_canary_secret" in lower:
        markers.add("ORTHUS_CANARY_SECRET")
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
        if _is_side_effecting_tool_name(tool_name):
            uses_prior_approval = bool(args.get("uses_prior_approval") or args.get("approval_ref") == "last_trusted_intent")
            if approved_event_id and current_event_id and approved_event_id != current_event_id:
                stale_or_cross_event_action_context = True
            if uses_prior_approval and session.last_trusted_intent_event_id and current_event_id:
                if session.last_trusted_intent_event_id != current_event_id:
                    stale_or_cross_event_action_context = True

        current_markers = _extract_sensitive_markers(args)
        tool_result_markers = _extract_sensitive_markers(args.get("_tool_result", ""))
        for marker in tool_result_markers:
            session.recent_sensitive_markers = _bounded_append(session.recent_sensitive_markers, marker)
        if _is_external_or_public_sink(tool_name, args) and current_markers:
            known_markers = set(session.recent_sensitive_markers)
            if any(marker in known_markers for marker in current_markers):
                multi_tool_exfiltration_chain = True

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

        return CERBERResult(
            trajectory_risk=rolling,
            risk_trend=trend,
            reason_codes=output_codes,
            updated_session_context=session.to_dict(),
        )
