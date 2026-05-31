from __future__ import annotations

from dataclasses import replace
from typing import List, Optional, Sequence

from .ast_nodes import (
    ExplainStatement,
    FilterCondition,
    HelpStatement,
    QueryOptions,
    ShowLatest,
    ShowPredictions,
    ShowStats,
    ShowThreats,
    ShowTraffic,
    Statement,
)
from .lexer import Lexer, Token


class Parser:
    def __init__(self, tokens: Sequence[Token]):
        self.tokens = list(tokens)
        self.position = 0

    def parse(self) -> Statement:
        if self._match_word("SHOW"):
            return self._parse_show()
        if self._match_word("HELP"):
            self._advance()
            return HelpStatement()
        if self._match_word("EXPLAIN"):
            return self._parse_explain()
        raise ValueError(f"Unknown command near token {self._peek().value!r}")

    def _parse_show(self) -> Statement:
        self._expect_word("SHOW")
        if self._match_word("THREATS"):
            self._advance()
            return ShowThreats(options=self._parse_query_options(default_limit=10))
        if self._match_word("TRAFFIC"):
            self._advance()
            return ShowTraffic(options=self._parse_query_options(default_limit=10))
        if self._match_word("PREDICTIONS"):
            self._advance()
            return ShowPredictions(options=self._parse_query_options(default_limit=20))
        if self._match_word("STATS"):
            self._advance()
            return ShowStats(options=self._parse_query_options(default_limit=1))
        if self._match_word("LATEST"):
            self._advance()
            return ShowLatest()
        raise ValueError("Expected THREATS, TRAFFIC, PREDICTIONS, STATS, or LATEST after SHOW")

    def _parse_explain(self) -> Statement:
        self._expect_word("EXPLAIN")
        parts: List[str] = []
        while not self._peek_kind("EOF"):
            token = self._advance()
            parts.append(token.value)
        return ExplainStatement(query=" ".join(parts).strip())

    def _parse_query_options(self, default_limit: Optional[int]) -> QueryOptions:
        limit = default_limit
        order_by = None
        order_direction = "DESC"
        filters: List[FilterCondition] = []

        while not self._peek_kind("EOF"):
            if self._match_word("LIMIT"):
                self._advance()
                limit = self._parse_integer()
                continue

            if self._match_word("TOP"):
                self._advance()
                limit = self._parse_integer()
                continue

            if self._match_word("ORDER"):
                self._advance()
                self._expect_word("BY")
                order_by = self._parse_field_name()
                if self._peek_kind("WORD") and self._peek().value.upper() in {"ASC", "DESC"}:
                    order_direction = self._advance().value.upper()
                continue

            if self._match_word("WHERE"):
                self._advance()
                filters.append(self._parse_filter())
                while self._peek_kind("WORD") and self._peek().value.upper() == "AND":
                    self._advance()
                    filters.append(self._parse_filter())
                continue

            break

        return QueryOptions(
            limit=limit,
            order_by=order_by,
            order_direction=order_direction,
            filters=tuple(filters),
        )

    def _parse_filter(self) -> FilterCondition:
        field = self._parse_field_name()
        operator = self._parse_operator()
        value = self._parse_literal()
        return FilterCondition(field=field, operator=operator, value=value)

    def _parse_field_name(self) -> str:
        token = self._advance()
        if token.kind != "WORD":
            raise ValueError(f"Expected field name near {token.value!r}")
        return token.value.lower()

    def _parse_operator(self) -> str:
        token = self._advance()
        if token.kind != "OP":
            raise ValueError(f"Expected comparison operator near {token.value!r}")
        return token.value

    def _parse_literal(self):
        token = self._advance()
        if token.kind == "NUMBER":
            return int(token.value) if token.value.isdigit() else float(token.value)
        if token.kind in {"WORD", "STRING"}:
            return token.value
        raise ValueError(f"Expected literal near {token.value!r}")

    def _parse_integer(self) -> int:
        token = self._advance()
        if token.kind != "NUMBER":
            raise ValueError(f"Expected number near {token.value!r}")
        return int(float(token.value))

    def _peek(self) -> Token:
        return self.tokens[self.position]

    def _advance(self) -> Token:
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _peek_kind(self, kind: str) -> bool:
        return self._peek().kind == kind

    def _match_word(self, word: str) -> bool:
        token = self._peek()
        return token.kind == "WORD" and token.value.upper() == word

    def _expect_word(self, word: str) -> None:
        token = self._advance()
        if token.kind != "WORD" or token.value.upper() != word:
            raise ValueError(f"Expected {word} near {token.value!r}")


def parse_dsl(text: str) -> Statement:
    lexer = Lexer()
    tokens = lexer.lex(text)
    return Parser(tokens).parse()
