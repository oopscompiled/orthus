"""
Policy engine - evaluates app-specific policy.yaml rules.
Layer 3 in the decision pipeline (after rules, before CERBER).

Reads developer-owned policy config:
  tools:
    refund_payment:
      risk: high
      require_approval_if:
        - args.amount > 100
        - actor.role != "manager"

Returns: PolicyDecision(decision, reason_codes, matched_policies)
"""

from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

from api.engine.reason_codes import (
    POLICY_ATTACHMENT_APPROVAL,
    POLICY_BLOCKED_DOMAIN,
    POLICY_BLOCK_IF_MATCHED,
    POLICY_LOG_ONLY,
    POLICY_REQUIRE_APPROVAL_ALWAYS,
    POLICY_REQUIRE_APPROVAL_CONDITION,
    policy_risk_level,
)

from .condition_eval import eval_condition
from .loaders import load_policy_dict, load_policy_yaml


@dataclass
class PolicyDecision:
    decision: Optional[str]  # None = no policy match, let pipeline continue
    reason_codes: list[str]
    matched_policies: list[str]
    risk_level: Optional[str] = None


class PolicyEngine:
    def __init__(self, policy_config: dict[str, Any]):
        self.config = policy_config

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        return cls(load_policy_yaml(path))

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> "PolicyEngine":
        return cls(load_policy_dict(config))

    def _tool_policy(self, action_name: str) -> dict[str, Any] | None:
        tools = self.config.get("tools", {})
        if not isinstance(tools, dict):
            return None
        tool = tools.get(action_name)
        return tool if isinstance(tool, dict) else None

    @staticmethod
    def _base_reason_codes(tool_policy: dict[str, Any]) -> list[str]:
        risk = str(tool_policy.get("risk", "")).lower()
        return [policy_risk_level(risk)] if risk else []

    @staticmethod
    def _extract_contact_value(args: dict[str, Any]) -> str | None:
        for key in ("to", "recipient", "email", "destination", "address"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _extract_domain(value: str) -> str | None:
        if "@" in value and " " not in value:
            domain = value.rsplit("@", 1)[-1].lower().strip()
            return domain or None

        parsed = urlparse(value)
        host = parsed.hostname
        return host.lower() if host else None

    @staticmethod
    def _has_attachments(args: dict[str, Any]) -> bool:
        for key in ("attachment", "attachments", "file", "files"):
            value = args.get(key)
            if value is None:
                continue
            if isinstance(value, list) and len(value) == 0:
                continue
            return True
        return False

    @staticmethod
    def _matches_any_condition(conditions: Any, context: dict[str, Any]) -> bool:
        if not isinstance(conditions, list):
            return False
        for condition in conditions:
            if isinstance(condition, str) and eval_condition(condition, context):
                return True
        return False

    def evaluate(
        self,
        action_name: str,
        args: dict[str, Any],
        actor: dict[str, Any],
        session: dict[str, Any],
    ) -> PolicyDecision:
        tool_policy = self._tool_policy(action_name)
        if not tool_policy:
            return PolicyDecision(decision=None, reason_codes=[], matched_policies=[])

        context: dict[str, Any] = {"args": args, "actor": actor, "session": session}
        base_codes = self._base_reason_codes(tool_policy)

        if self._matches_any_condition(tool_policy.get("block_if"), context):
            return PolicyDecision(
                decision="block",
                reason_codes=[POLICY_BLOCK_IF_MATCHED, *base_codes],
                matched_policies=[f"tools.{action_name}.block_if"],
                risk_level=str(tool_policy.get("risk", "")).lower() or None,
            )

        blocked_domains = tool_policy.get("block_external_domains")
        if isinstance(blocked_domains, list) and blocked_domains:
            contact = self._extract_contact_value(args)
            if contact:
                domain = self._extract_domain(contact)
                normalized_domains = {str(item).lower() for item in blocked_domains}
                if domain and domain in normalized_domains:
                    return PolicyDecision(
                        decision="block",
                        reason_codes=[POLICY_BLOCKED_DOMAIN, *base_codes],
                        matched_policies=[f"tools.{action_name}.block_external_domains"],
                        risk_level=str(tool_policy.get("risk", "")).lower() or None,
                    )

        if tool_policy.get("require_approval") == "always":
            return PolicyDecision(
                decision="require_approval",
                reason_codes=[POLICY_REQUIRE_APPROVAL_ALWAYS, *base_codes],
                matched_policies=[f"tools.{action_name}.require_approval"],
                risk_level=str(tool_policy.get("risk", "")).lower() or None,
            )

        if self._matches_any_condition(tool_policy.get("require_approval_if"), context):
            return PolicyDecision(
                decision="require_approval",
                reason_codes=[POLICY_REQUIRE_APPROVAL_CONDITION, *base_codes],
                matched_policies=[f"tools.{action_name}.require_approval_if"],
                risk_level=str(tool_policy.get("risk", "")).lower() or None,
            )

        if bool(tool_policy.get("require_approval_for_attachments")) and self._has_attachments(args):
            return PolicyDecision(
                decision="require_approval",
                reason_codes=[POLICY_ATTACHMENT_APPROVAL, *base_codes],
                matched_policies=[f"tools.{action_name}.require_approval_for_attachments"],
                risk_level=str(tool_policy.get("risk", "")).lower() or None,
            )

        if str(tool_policy.get("risk", "")).lower() == "low" and bool(tool_policy.get("log")):
            return PolicyDecision(
                decision="log_only",
                reason_codes=[POLICY_LOG_ONLY, *base_codes],
                matched_policies=[f"tools.{action_name}.log"],
                risk_level=str(tool_policy.get("risk", "")).lower() or None,
            )

        return PolicyDecision(decision=None, reason_codes=[], matched_policies=[])
