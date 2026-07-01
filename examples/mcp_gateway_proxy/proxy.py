"""Dependency-free MCP gateway/proxy simulation guarded by Orthus.

This is not a full MCP server or proxy. It shows the control pattern Orthus is
built for: inspect MCP-style operations at the boundary before the operation is
forwarded to a server or executed by the host application.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, FirewallResult, ToolCall

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_request(event: dict[str, Any], session_context: dict[str, object] | None = None) -> FirewallRequest:
    tool_call = event["tool_call"]
    actor = event.get("actor", {})
    return FirewallRequest(
        text=event.get("text"),
        tool_call=ToolCall(
            name=tool_call["name"],
            args=dict(tool_call.get("args") or {}),
            description=tool_call.get("description"),
            result=tool_call.get("result"),
        ),
        actor=Actor(user_id=actor.get("user_id"), role=actor.get("role")),
        session_context=dict(session_context or event.get("session_context") or {}),
    )


def guard_mcp_event(event: dict[str, Any], *, firewall: FirewallEngine | None = None) -> FirewallResult:
    engine = firewall or FirewallEngine()
    return engine.validate_action(build_request(event))


def build_demo_events() -> list[dict[str, Any]]:
    return [load_fixture(path) for path in sorted(FIXTURES_DIR.glob("*.json"))]


def run_demo(*, as_json: bool = False, print_output: bool = True) -> list[dict[str, Any]]:
    firewall = FirewallEngine()
    rows: list[dict[str, Any]] = []
    for event in build_demo_events():
        result = guard_mcp_event(event, firewall=firewall)
        rows.append({
            "id": event["id"],
            "title": event["title"],
            "tool": event["tool_call"]["name"],
            "decision": result.decision,
            "risk": result.risk,
            "reason_codes": result.reason_codes,
            "matched_rules": result.matched_rules,
        })

    if print_output:
        if as_json:
            for row in rows:
                print(json.dumps(row, ensure_ascii=False))
        else:
            print("ORTHUS MCP GATEWAY/PROXY SIMULATION")
            print("Validate MCP-style operations before forwarding them to the server or host tools.")
            print()
            print(f"{'Fixture':<36} | {'Tool':<18} | {'Decision':<16} | {'Risk':<5} | Reason codes")
            print("-" * 140)
            for row in rows:
                reasons = ", ".join(row["reason_codes"]) if row["reason_codes"] else "-"
                print(f"{row['id'][:36]:<36} | {row['tool'][:18]:<18} | {row['decision']:<16} | {row['risk']:<5.2f} | {reasons}")
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Orthus MCP gateway/proxy simulation")
    parser.add_argument("--json", action="store_true", help="Output JSON lines")
    args = parser.parse_args(argv)
    run_demo(as_json=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
