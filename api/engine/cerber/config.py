"""Static CERBER scoring configuration."""

from __future__ import annotations

SENSITIVE_TOOLS = {
    "export_customer_data",
    "refund_payment",
    "change_plan",
    "delete_record",
    "delete_user",
    "grant_admin",
    "send_email",
}

RECENT_REASON_CODES_LIMIT = 20
HIGH_VELOCITY_THRESHOLD = 8
SECURITY_RISK_MIN = 0.50
RISING_DELTA = 0.20
FALLING_DELTA = -0.05

SECURITY_REASON_CODES = {
    "instruction_override_attempt",
    "system_override_attempt",
    "role_override_attempt",
    "system_prompt_extraction",
    "hidden_instruction_marker",
    "mcp_tool_side_effect",
    "mcp_hidden_tool_chain",
    "refund_to_attacker",
    "external_destination",
    "sensitive_tool_invocation",
}

LOW_IMPACT_REASON_CODES = {
    "instruction_override_soft",
    "business_context_override",
    "meta_security_discussion",
    "policy_log_only",
}

WEIGHTS = {
    "decision_risk": 0.35,
    "blocked_attempts": 0.20,
    "sensitive_actions": 0.20,
    "velocity": 0.15,
    "prompt_injection_recent": 0.10,
}

SMOOTHING_ALPHA = 0.40
