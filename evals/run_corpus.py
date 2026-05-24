from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.engine.pipeline import Actor, FirewallEngine, FirewallRequest, ToolCall


@dataclass(slots=True)
class LoadedCase:
    data: dict[str, Any]
    file: str
    line: int


def load_jsonl_files(path: Path) -> list[LoadedCase]:
    files: list[Path]
    if path.is_file():
        files = [path]
    else:
        files = sorted(path.rglob("*.jsonl"))

    out: list[LoadedCase] = []
    for file in files:
        for i, line in enumerate(file.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            data = json.loads(stripped)
            out.append(LoadedCase(data=data, file=str(file), line=i))
    return out


def _select_expect(case: dict[str, Any], *, strict_pro: bool) -> dict[str, Any] | None:
    tier = str(case.get("tier", "basic"))

    if tier == "basic":
        return case.get("expect") or case.get("expect_basic")

    # pro/private defaults to expect_basic when available
    if tier in {"pro_candidate", "private_intel"}:
        if strict_pro:
            exp = case.get("expect_pro")
            if isinstance(exp, dict):
                machine_keys = {
                    "decision",
                    "decision_in",
                    "must_match",
                    "must_not_match",
                    "must_reason_codes",
                    "must_not_reason_codes",
                    "min_risk",
                    "max_risk",
                    "routes_include",
                    "flags_include",
                    "flags_exclude",
                }
                if any(k in exp for k in machine_keys):
                    return exp
            return None
        return case.get("expect_basic") or case.get("expect")

    return case.get("expect") or case.get("expect_basic")


def build_request(raw: dict[str, Any], session_context: dict[str, object] | None) -> FirewallRequest:
    if "request" in raw and isinstance(raw["request"], dict):
        raw = raw["request"]

    tool_call_raw = raw.get("tool_call") if isinstance(raw.get("tool_call"), dict) else None
    actor_raw = raw.get("actor") if isinstance(raw.get("actor"), dict) else None

    tool_call = None
    if tool_call_raw is not None:
        tool_call = ToolCall(
            name=str(tool_call_raw.get("name", "")),
            args=dict(tool_call_raw.get("args") or {}),
            description=tool_call_raw.get("description"),
            result=tool_call_raw.get("result"),
        )

    actor = None
    if actor_raw is not None:
        actor = Actor(
            user_id=str(actor_raw.get("user_id")) if actor_raw.get("user_id") is not None else None,
            role=str(actor_raw.get("role")) if actor_raw.get("role") is not None else None,
        )

    context = session_context if session_context is not None else raw.get("session_context")

    return FirewallRequest(
        text=raw.get("text"),
        tool_call=tool_call,
        actor=actor,
        session_context=dict(context or {}),
    )


def evaluate_expectation(result, expect: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if "decision" in expect and result.decision != expect["decision"]:
        errors.append(f"expected decision={expect['decision']} got={result.decision}")

    if "decision_in" in expect and result.decision not in set(expect["decision_in"]):
        errors.append(f"expected decision_in={expect['decision_in']} got={result.decision}")
    for denied in expect.get("must_not_decision", []):
        if result.decision == denied:
            errors.append(f"expected must_not_decision {denied}")

    for rid in expect.get("must_match", []):
        if rid not in result.matched_rules:
            errors.append(f"expected must_match {rid}")

    for rid in expect.get("must_not_match", []):
        if rid in result.matched_rules:
            errors.append(f"expected must_not_match {rid}")

    for reason in expect.get("must_reason_codes", []):
        if reason not in result.reason_codes:
            errors.append(f"expected must_reason_codes {reason}")

    for reason in expect.get("must_not_reason_codes", []):
        if reason in result.reason_codes:
            errors.append(f"expected must_not_reason_codes {reason}")

    if "min_risk" in expect and float(result.risk) < float(expect["min_risk"]):
        errors.append(f"expected min_risk {expect['min_risk']} got={result.risk}")

    if "max_risk" in expect and float(result.risk) > float(expect["max_risk"]):
        errors.append(f"expected max_risk {expect['max_risk']} got={result.risk}")

    for route in expect.get("routes_include", []):
        if route not in result.routes:
            errors.append(f"expected routes_include {route}")

    for flag in expect.get("flags_include", []):
        if flag not in result.flags:
            errors.append(f"expected flags_include {flag}")

    for flag in expect.get("flags_exclude", []):
        if flag in result.flags:
            errors.append(f"expected flags_exclude {flag}")

    return errors


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = int(math.ceil((q / 100.0) * len(sorted_vals))) - 1
    idx = max(0, min(idx, len(sorted_vals) - 1))
    return float(sorted_vals[idx])


def run_single_case(
    engine: FirewallEngine,
    loaded: LoadedCase,
    *,
    strict_pro: bool,
    debug_failures: bool,
) -> dict[str, Any]:
    case = loaded.data
    case_id = str(case.get("id", f"{loaded.file}:{loaded.line}"))

    expect = _select_expect(case, strict_pro=strict_pro)
    if expect is None:
        return {
            "id": case_id,
            "file": loaded.file,
            "tier": str(case.get("tier", "unknown")),
            "passed": True,
            "skipped": True,
            "messages": ["no machine-checkable expectation"],
        }

    req = build_request(case, None)
    result = engine.validate_action(req)
    errors = evaluate_expectation(result, expect)

    entry = {
        "id": case_id,
        "file": loaded.file,
        "tier": str(case.get("tier", "unknown")),
        "passed": not errors,
        "decision": result.decision,
        "risk": result.risk,
        "matched_rules": list(result.matched_rules),
        "reason_codes": list(result.reason_codes),
        "latency_ms": float(result.latency_ms),
        "messages": errors,
    }
    if debug_failures and errors:
        entry["routes"] = list(result.routes)
        entry["flags"] = list(result.flags)
        entry["normalized"] = result.normalized
    return entry


def run_sequence_case(
    engine: FirewallEngine,
    loaded: LoadedCase,
    *,
    strict_pro: bool,
    debug_failures: bool,
) -> dict[str, Any]:
    case = loaded.data
    case_id = str(case.get("id", f"{loaded.file}:{loaded.line}"))
    steps = case.get("steps") or []

    session_context: dict[str, object] = {}
    step_results: list[dict[str, Any]] = []
    all_errors: list[str] = []

    for idx, step in enumerate(steps, start=1):
        req = build_request(step, session_context)
        result = engine.validate_action(req)
        session_context = dict(result.updated_session_context)

        expect = step.get("expect")
        errors: list[str] = []
        if isinstance(expect, dict):
            errors = evaluate_expectation(result, expect)
            all_errors.extend([f"step {idx}: {e}" for e in errors])

        step_entry = {
            "step": idx,
            "passed": not errors,
            "decision": result.decision,
            "risk": result.risk,
            "matched_rules": list(result.matched_rules),
            "reason_codes": list(result.reason_codes),
            "latency_ms": float(result.latency_ms),
            "messages": errors,
        }
        if debug_failures and errors:
            step_entry["routes"] = list(result.routes)
            step_entry["flags"] = list(result.flags)
            step_entry["normalized"] = result.normalized
        step_results.append(step_entry)

    entry = {
        "id": case_id,
        "file": loaded.file,
        "tier": str(case.get("tier", "unknown")),
        "passed": not all_errors,
        "decision": step_results[-1]["decision"] if step_results else "allow",
        "risk": step_results[-1]["risk"] if step_results else 0.0,
        "matched_rules": step_results[-1]["matched_rules"] if step_results else [],
        "reason_codes": step_results[-1]["reason_codes"] if step_results else [],
        "latency_ms": float(sum(s["latency_ms"] for s in step_results)),
        "messages": all_errors,
        "steps": step_results,
    }
    return entry


def summarize_results(corpus: str, stateful: bool, cases: list[dict[str, Any]], wall_ms: float) -> dict[str, Any]:
    total = len(cases)
    skipped = sum(1 for c in cases if c.get("skipped"))
    failed = sum(1 for c in cases if not c.get("passed", False) and not c.get("skipped", False))
    passed = total - skipped - failed

    decision_distribution: dict[str, int] = {}
    latencies = [float(c.get("latency_ms", 0.0)) for c in cases if "latency_ms" in c]
    for c in cases:
        d = c.get("decision")
        if isinstance(d, str):
            decision_distribution[d] = decision_distribution.get(d, 0) + 1

    failures = [
        {
            "case_id": c.get("id"),
            "file": c.get("file"),
            "step": None,
            "messages": c.get("messages", []),
            "decision": c.get("decision"),
            "risk": c.get("risk"),
            "matched_rules": c.get("matched_rules", []),
            "reason_codes": c.get("reason_codes", []),
        }
        for c in cases
        if not c.get("passed", False) and not c.get("skipped", False)
    ]

    return {
        "corpus": corpus,
        "stateful": stateful,
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "fail_rate": round((failed / total) * 100.0, 2) if total else 0.0,
        "decision_distribution": decision_distribution,
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 4) if latencies else 0.0,
            "p50": round(_percentile(latencies, 50), 4),
            "p95": round(_percentile(latencies, 95), 4),
            "p99": round(_percentile(latencies, 99), 4),
            "wall": round(wall_ms, 4),
        },
        "failures": failures,
        "cases": cases,
    }


def _print_pretty(report: dict[str, Any], *, quiet: bool) -> None:
    if quiet:
        return
    print("ORTHUS EVAL REPORT")
    print(f"Corpus: {report['corpus']}")
    print(f"Mode: {'stateful' if report['stateful'] else 'stateless/auto'}")
    print(f"Cases: {report['total']}")
    print(f"Passed: {report['passed']}")
    print(f"Failed: {report['failed']}")
    print(f"Skipped: {report['skipped']}")
    print(f"Fail rate: {report['fail_rate']}%")
    print()

    print("Decision distribution:")
    for k, v in sorted(report["decision_distribution"].items()):
        print(f"{k}: {v}")
    print()

    lat = report["latency_ms"]
    print("Latency:")
    print(f"mean: {lat['mean']} ms")
    print(f"p50: {lat['p50']} ms")
    print(f"p95: {lat['p95']} ms")
    print(f"p99: {lat['p99']} ms")
    print(f"wall: {lat['wall']} ms")
    print()

    if report["failures"]:
        print("Failures:")
        for f in report["failures"]:
            print(f"- {f['case_id']} ({f['file']})")
            for msg in f.get("messages", []):
                print(f"  {msg}")
            print(
                f"  got decision={f.get('decision')} risk={f.get('risk')} "
                f"matched_rules={f.get('matched_rules')} reason_codes={f.get('reason_codes')}"
            )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Orthus corpus eval harness")
    parser.add_argument("--corpus", required=True, help="JSONL file or directory")
    parser.add_argument("--stateful", action="store_true", help="Treat steps cases as sequences")
    parser.add_argument("--tier", default=None, help="Filter by tier")
    parser.add_argument("--kind", default=None, help="Filter by kind")
    parser.add_argument("--json", action="store_true", help="Print JSON report")
    parser.add_argument("--output", default=None, help="Write JSON report to file")
    parser.add_argument("--no-fail", action="store_true", help="Always exit 0")
    parser.add_argument("--quiet", action="store_true", help="Reduce stdout")
    parser.add_argument("--limit", type=int, default=None, help="Run first N cases")
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first failed case")
    parser.add_argument("--debug-failures", action="store_true", help="Include details for failures")
    parser.add_argument("--strict-pro", action="store_true", help="Evaluate expect_pro machine fields when present")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    corpus_path = Path(args.corpus)
    loaded = load_jsonl_files(corpus_path)

    filtered: list[LoadedCase] = []
    for item in loaded:
        tier = str(item.data.get("tier", "basic"))
        if args.tier and tier != args.tier:
            continue
        if args.kind and str(item.data.get("kind")) != args.kind:
            continue
        filtered.append(item)

    if args.limit is not None:
        filtered = filtered[: max(0, args.limit)]

    engine = FirewallEngine()
    case_entries: list[dict[str, Any]] = []

    start = time.perf_counter()
    for item in filtered:
        case = item.data
        has_steps = isinstance(case.get("steps"), list)
        is_stateful = bool(args.stateful or has_steps)

        if is_stateful and has_steps:
            entry = run_sequence_case(
                engine,
                item,
                strict_pro=args.strict_pro,
                debug_failures=args.debug_failures,
            )
        elif has_steps:
            entry = {
                "id": str(case.get("id", f"{item.file}:{item.line}")),
                "file": item.file,
                "tier": str(case.get("tier", "unknown")),
                "passed": True,
                "skipped": True,
                "messages": ["sequence case skipped in stateless mode"],
            }
        else:
            entry = run_single_case(
                engine,
                item,
                strict_pro=args.strict_pro,
                debug_failures=args.debug_failures,
            )

        case_entries.append(entry)

        if args.fail_fast and not entry.get("passed", False) and not entry.get("skipped", False):
            break

    wall_ms = (time.perf_counter() - start) * 1000.0
    report = summarize_results(str(corpus_path), bool(args.stateful), case_entries, wall_ms)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_pretty(report, quiet=args.quiet)

    if report["failed"] > 0 and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
