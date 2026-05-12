"""Shared reason codes used across pipeline layers."""

# Policy reason codes
POLICY_BLOCK_IF_MATCHED = "policy_block_condition_matched"
POLICY_REQUIRE_APPROVAL_ALWAYS = "policy_require_approval_always"
POLICY_REQUIRE_APPROVAL_CONDITION = "policy_require_approval_condition"
POLICY_BLOCKED_DOMAIN = "policy_blocked_domain"
POLICY_ATTACHMENT_APPROVAL = "policy_attachment_requires_approval"
POLICY_LOG_ONLY = "policy_log_only"


def policy_risk_level(level: str) -> str:
    return f"policy_risk_{str(level).lower()}"
