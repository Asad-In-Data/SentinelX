from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Backend.compiler.engine import DSLExecutor, DSLResult, render_result  # noqa: E402
from Backend.compiler.datasource import DataRepository, SourceResult  # noqa: E402

CLI_VERSION = "2.0.0"


def _result_from_source(command: str, source_result: SourceResult, summary: str) -> DSLResult:
    columns = list(source_result.rows[0].keys()) if source_result.rows else []
    return DSLResult(
        command=command,
        source=source_result.source,
        columns=columns,
        rows=source_result.rows,
        summary=f"{summary} ({len(source_result.rows)} row(s) from {source_result.source})",
    )


def _normalize(command: str) -> str:
    return command.replace(" ", "").replace("_", "").upper()


def _dispatch_special(command: str, repository: DataRepository) -> DSLResult | None:
    normalized = _normalize(command)

    if normalized == "HELP":
        return _result_from_source("HELP", repository.help_rows(), "Available commands")

    if normalized == "VERSION":
        return DSLResult(
            command="VERSION",
            source="local",
            columns=["version"],
            rows=[{"version": CLI_VERSION}],
            summary=f"SentinelX DSL version {CLI_VERSION}",
        )

    if normalized == "STATUS":
        return _result_from_source("STATUS", repository.system_status(), "System status")

    if normalized == "SHOWTHREATS":
        return _result_from_source("SHOW_THREATS", repository.fetch_threats(limit=20), "Threat rows")

    if normalized == "SHOWTRAFFIC":
        return _result_from_source("SHOW_TRAFFIC", repository.fetch_traffic(limit=20), "Traffic snapshots")

    if normalized == "SHOWIPS":
        return _result_from_source("SHOW_IPS", repository.fetch_ips(limit=20), "Unique IPs")

    if normalized == "SHOWPROTOCOLS":
        return _result_from_source("SHOW_PROTOCOLS", repository.fetch_protocols(limit=20), "Protocol counts")

    if normalized == "COUNTPACKETS":
        return _result_from_source("COUNT_PACKETS", repository.count_packets(), "Packet total")

    if normalized == "COUNTTHREATS":
        return _result_from_source("COUNT_THREATS", repository.count_threats(), "Threat total")

    if normalized == "COUNTIPS":
        return _result_from_source("COUNT_IPS", repository.count_ips(), "IP total")

    if normalized == "SHOWHIGHRISK":
        return _result_from_source("SHOW_HIGH_RISK", repository.fetch_risk("HIGH", limit=20), "High-risk rows")

    if normalized == "SHOWMEDIUMRISK":
        return _result_from_source("SHOW_MEDIUM_RISK", repository.fetch_risk("MEDIUM", limit=20), "Medium-risk rows")

    if normalized == "SHOWLOWRISK":
        return _result_from_source("SHOW_LOW_RISK", repository.fetch_risk("LOW", limit=20), "Low-risk rows")

    if normalized == "SHOWTCP":
        return _result_from_source("SHOW_TCP", repository.fetch_protocol("tcp", limit=20), "TCP rows")

    if normalized == "SHOWUDP":
        return _result_from_source("SHOW_UDP", repository.fetch_protocol("udp", limit=20), "UDP rows")

    if normalized == "SHOWICMP":
        return _result_from_source("SHOW_ICMP", repository.fetch_protocol("icmp", limit=20), "ICMP rows")

    if normalized == "LATESTTHREATS":
        return _result_from_source("LATEST_THREATS", repository.latest_threats(limit=5), "Latest threats")

    if normalized == "LATESTPACKETS":
        return _result_from_source("LATEST_PACKETS", repository.latest_packets(limit=5), "Latest packets")

    if normalized == "TOPATTACKERS":
        return _result_from_source("TOP_ATTACKERS", repository.top_attackers(limit=10), "Top attackers")

    return None


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelx-dsl", description="SentinelX mini DSL")
    parser.add_argument("query", nargs="*", help="DSL query, e.g. show predictions limit 10")
    parser.add_argument("--api-base", default=None, help="Fallback API base URL")
    args = parser.parse_args()

    repository = DataRepository()
    executor = DSLExecutor(repository=repository)
    if args.api_base:
        repository.api_base = args.api_base.rstrip("/")

    if args.query:
        query = " ".join(args.query)
        result = _dispatch_special(query, repository)
        if result is None:
            result = executor.execute(query)
        print(render_result(result))
        return

    print("SentinelX DSL REPL. Type a command or Ctrl+C to exit.")
    while True:
        try:
            query = input("dsl> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if not query:
            continue
        result = _dispatch_special(query, repository)
        if result is None:
            result = executor.execute(query)
        print(render_result(result))


if __name__ == "__main__":
    main()
