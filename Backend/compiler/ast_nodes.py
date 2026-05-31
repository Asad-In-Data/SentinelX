from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Any


@dataclass(frozen=True)
class FilterCondition:
    field: str
    operator: str
    value: Any


@dataclass(frozen=True)
class QueryOptions:
    limit: Optional[int] = None
    order_by: Optional[str] = None
    order_direction: str = "DESC"
    filters: Sequence[FilterCondition] = field(default_factory=tuple)


@dataclass(frozen=True)
class Statement:
    pass


@dataclass(frozen=True)
class ShowThreats(Statement):
    options: QueryOptions = QueryOptions(limit=10)


@dataclass(frozen=True)
class ShowTraffic(Statement):
    options: QueryOptions = QueryOptions(limit=10)


@dataclass(frozen=True)
class ShowPredictions(Statement):
    options: QueryOptions = QueryOptions(limit=20)


@dataclass(frozen=True)
class ShowStats(Statement):
    options: QueryOptions = QueryOptions(limit=1)


@dataclass(frozen=True)
class ShowLatest(Statement):
    pass


@dataclass(frozen=True)
class HelpStatement(Statement):
    pass


@dataclass(frozen=True)
class ExplainStatement(Statement):
    query: str
