from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Backend.compiler.engine import DSLExecutor, render_result  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelx-dsl", description="SentinelX mini DSL")
    parser.add_argument("query", nargs="*", help="DSL query, e.g. show predictions limit 10")
    parser.add_argument("--api-base", default=None, help="Fallback API base URL")
    args = parser.parse_args()

    executor = DSLExecutor()
    if args.api_base:
        executor.repository.api_base = args.api_base.rstrip("/")

    if args.query:
        query = " ".join(args.query)
        result = executor.execute(query)
        print(render_result(result))
        return

    print("SentinelX DSL REPL. Type 'help' or Ctrl+C to exit.")
    while True:
        try:
            query = input("dsl> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if not query:
            continue
        result = executor.execute(query)
        print(render_result(result))


if __name__ == "__main__":
    main()
