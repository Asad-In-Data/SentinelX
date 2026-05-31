from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from .ast_nodes import ExplainStatement, HelpStatement, ShowLatest, ShowPredictions, ShowStats, ShowThreats, ShowTraffic, Statement
from .datasource import DataRepository, SourceResult
from .parser import parse_dsl


@dataclass(frozen=True)
class DSLResult:
    command: str
    source: str
    columns: List[str]
    rows: List[Dict[str, Any]]
    summary: str


class DSLExecutor:
    def __init__(self, repository: Optional[DataRepository] = None):
        self.repository = repository or DataRepository()

    def execute(self, query: str) -> DSLResult:
        statement = parse_dsl(query)
        return self._execute_statement(statement)

    def _execute_statement(self, statement: Statement) -> DSLResult:
        if isinstance(statement, ShowThreats):
            result = self.repository.fetch_threats(
                limit=statement.options.limit or 10,
                filters=statement.options.filters,
                order_by=statement.options.order_by,
                order_direction=statement.options.order_direction,
            )
            return self._result_from_source("SHOW THREATS", result, "Threat rows")

        if isinstance(statement, ShowTraffic):
            result = self.repository.fetch_traffic(limit=statement.options.limit or 10)
            return self._result_from_source("SHOW TRAFFIC", result, "Traffic snapshots")

        if isinstance(statement, ShowPredictions):
            result = self.repository.fetch_predictions(limit=statement.options.limit or 20)
            return self._result_from_source("SHOW PREDICTIONS", result, "All recent predictions")

        if isinstance(statement, ShowStats):
            result = self.repository.fetch_stats()
            return self._result_from_source("SHOW STATS", result, "Current live summary")

        if isinstance(statement, ShowLatest):
            result = self.repository.fetch_latest()
            return self._result_from_source("SHOW LATEST", result, "Latest prediction")

        if isinstance(statement, HelpStatement):
            result = self.repository.help_rows()
            return self._result_from_source("HELP", result, "Available DSL commands")

        if isinstance(statement, ExplainStatement):
            result = self.repository.explain_rows(statement.query)
            return self._result_from_source("EXPLAIN", result, "Query execution path")

        raise ValueError(f"Unsupported statement: {type(statement).__name__}")

    @staticmethod
    def _result_from_source(command: str, result: SourceResult, summary: str) -> DSLResult:
        columns = list(result.rows[0].keys()) if result.rows else []
        return DSLResult(
            command=command,
            source=result.source,
            columns=columns,
            rows=result.rows,
            summary=f"{summary} ({len(result.rows)} row(s) from {result.source})",
        )


def render_result(result: DSLResult) -> str:
    if not result.rows:
        return f"{result.command} | source={result.source}\nNo rows found."

    widths = {column: len(column) for column in result.columns}
    for row in result.rows:
        for column in result.columns:
            widths[column] = max(widths[column], len(_stringify(row.get(column))))

    header = " | ".join(column.ljust(widths[column]) for column in result.columns)
    separator = "-+-".join("-" * widths[column] for column in result.columns)
    lines = [f"{result.command} | source={result.source}", result.summary, header, separator]
    for row in result.rows:
        lines.append(" | ".join(_stringify(row.get(column)).ljust(widths[column]) for column in result.columns))
    return "\n".join(lines)


def _stringify(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass
    return str(value)
