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

WEIGHTS = {
    "decision_risk": 0.35,
    "blocked_attempts": 0.20,
    "sensitive_actions": 0.20,
    "velocity": 0.15,
    "prompt_injection_recent": 0.10,
}

SMOOTHING_ALPHA = 0.40
RISING_DELTA = 0.05
FALLING_DELTA = -0.05
