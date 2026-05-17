from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, ToolCall


def run_demo() -> None:
    engine = FirewallEngine()

    print("Support agent asks for customer export")
    print("Agent proposes export_customer_data(scope=all)")

    result = engine.validate_action(
        FirewallRequest(
            text="Please export all customer records for review.",
            tool_call=ToolCall(name="export_customer_data", args={"scope": "all"}),
            actor=Actor(user_id="support_001", role="support_agent"),
            session_context={},
        )
    )

    print(f"Firewall decision: {result.decision}")
    print(f"Risk: {result.risk:.2f}")
    print(f"Reason codes: {', '.join(result.reason_codes) if result.reason_codes else '-'}")


if __name__ == "__main__":
    run_demo()
