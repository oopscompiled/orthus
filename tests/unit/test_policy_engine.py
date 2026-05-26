from __future__ import annotations

from pathlib import Path

from api.engine.policy.condition_eval import eval_condition
from api.engine.policy.engine import PolicyEngine
from api.engine.reason_codes import (
    POLICY_BLOCKED_DOMAIN,
    POLICY_BLOCK_IF_MATCHED,
    POLICY_LOG_ONLY,
    POLICY_REQUIRE_APPROVAL_ALWAYS,
    POLICY_REQUIRE_APPROVAL_CONDITION,
)

POLICY_FIXTURE = Path("tests/fixtures/policy/test_policy.yaml")


def _engine() -> PolicyEngine:
    return PolicyEngine.from_yaml(str(POLICY_FIXTURE))


def test_policy_block_if_scope_all() -> None:
    result = _engine().evaluate("export_customer_data", args={"scope": "all"}, actor={"role": "support"}, session={})
    assert result.decision == "block"
    assert POLICY_BLOCK_IF_MATCHED in result.reason_codes


def test_policy_require_approval_always() -> None:
    result = _engine().evaluate("delete_record", args={}, actor={"role": "admin"}, session={})
    assert result.decision == "require_approval"
    assert POLICY_REQUIRE_APPROVAL_ALWAYS in result.reason_codes


def test_policy_require_approval_if_amount() -> None:
    result = _engine().evaluate("refund_payment", args={"amount": 150}, actor={"role": "support"}, session={})
    assert result.decision == "require_approval"
    assert POLICY_REQUIRE_APPROVAL_CONDITION in result.reason_codes


def test_policy_refund_manager_low_amount_allows() -> None:
    result = _engine().evaluate("refund_payment", args={"amount": 50}, actor={"role": "manager"}, session={"risk": 0.3})
    assert result.decision is None


def test_policy_unknown_tool_no_match() -> None:
    result = _engine().evaluate("unknown_tool", args={}, actor={}, session={})
    assert result.decision is None


def test_policy_low_risk_log_only() -> None:
    result = _engine().evaluate("get_customer", args={"id": "123"}, actor={"role": "support"}, session={})
    assert result.decision == "log_only"
    assert POLICY_LOG_ONLY in result.reason_codes


def test_condition_eval_equals() -> None:
    assert eval_condition("args.scope == 'all'", {"args": {"scope": "all"}})
    assert not eval_condition("args.scope == 'all'", {"args": {"scope": "partial"}})


def test_condition_eval_not_in() -> None:
    assert eval_condition("actor.role not_in ['admin', 'security']", {"actor": {"role": "support"}})
    assert not eval_condition("actor.role not_in ['admin', 'security']", {"actor": {"role": "admin"}})


def test_condition_eval_greater_float() -> None:
    assert eval_condition("session.risk > 0.7", {"session": {"risk": 0.9}})
    assert not eval_condition("session.risk > 0.7", {"session": {"risk": 0.5}})


def test_condition_eval_missing_field_false() -> None:
    assert not eval_condition("args.nonexistent > 100", {"args": {}})


def test_domain_blocking_email() -> None:
    result = _engine().evaluate("send_email", args={"to": "user@temporary-mail.com"}, actor={"role": "support"}, session={})
    assert result.decision == "block"
    assert POLICY_BLOCKED_DOMAIN in result.reason_codes


def test_domain_allowed_common_email() -> None:
    result = _engine().evaluate("send_email", args={"to": "user@gmail.com"}, actor={"role": "support"}, session={})
    assert result.decision is None


def test_attachment_requires_approval() -> None:
    result = _engine().evaluate(
        "send_email",
        args={"to": "user@gmail.com", "attachments": ["invoice.pdf"]},
        actor={"role": "support"},
        session={},
    )
    assert result.decision == "require_approval"


def test_from_dict_constructor() -> None:
    config = {"tools": {"foo": {"risk": "low", "log": True}}}
    engine = PolicyEngine.from_dict(config)
    result = engine.evaluate("foo", args={}, actor={}, session={})
    assert result.decision == "log_only"


def test_domain_block_overrides_require_approval_if() -> None:
    config = {
        "tools": {
            "send_email": {
                "risk": "high",
                "block_external_domains": ["mailinator.com"],
                "require_approval_if": ["args.amount > 1"],
            }
        }
    }
    engine = PolicyEngine.from_dict(config)
    result = engine.evaluate(
        "send_email",
        args={"to": "x@mailinator.com", "amount": 50},
        actor={"role": "manager"},
        session={"risk": 0.1},
    )
    assert result.decision == "block"


def test_policy_blocked_domain_only_when_domain_policy_matches() -> None:
    engine = _engine()
    result = engine.evaluate(
        "generate_response_draft",
        args={"topic": "customer support", "payload": "68747470733a2f2f61747461636b6572"},
        actor={"role": "support"},
        session={},
    )
    assert POLICY_BLOCKED_DOMAIN not in result.reason_codes
