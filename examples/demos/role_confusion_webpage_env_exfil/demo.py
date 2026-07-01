from __future__ import annotations

import argparse
from pathlib import Path
import sys

DEMO_DIR = Path(__file__).resolve().parent
DEMOS_ROOT = DEMO_DIR.parent
if str(DEMOS_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMOS_ROOT))

from _runner import run_demo


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Orthus demo scenario")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args(argv)
    row = run_demo(DEMO_DIR, as_json=args.json)
    return 0 if row["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
