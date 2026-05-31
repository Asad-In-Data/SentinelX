from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    position: int


class Lexer:
    """Tiny lexer for the SentinelX DSL.

    The language is intentionally compact:
    - keywords: SHOW, THREATS, TRAFFIC, STATS, LATEST, HELP, WHERE, LIMIT, ORDER, BY
    - operators: = != > < >= <=
    - literals: numbers, words, quoted strings
    """

    _multi_ops = {">=", "<=", "!="}
    _single_ops = {"=", ">", "<"}

    def lex(self, text: str) -> List[Token]:
        tokens: List[Token] = []
        i = 0
        length = len(text)

        while i < length:
            char = text[i]

            if char.isspace():
                i += 1
                continue

            if char in {"'", '"'}:
                quote = char
                start = i
                i += 1
                value = []
                while i < length:
                    current = text[i]
                    if current == quote:
                        break
                    if current == "\\" and i + 1 < length:
                        i += 1
                        value.append(text[i])
                    else:
                        value.append(current)
                    i += 1
                if i >= length or text[i] != quote:
                    raise ValueError(f"Unterminated string at position {start}")
                tokens.append(Token("STRING", "".join(value), start))
                i += 1
                continue

            pair = text[i : i + 2]
            if pair in self._multi_ops:
                tokens.append(Token("OP", pair, i))
                i += 2
                continue

            if char in self._single_ops:
                tokens.append(Token("OP", char, i))
                i += 1
                continue

            if char.isdigit():
                start = i
                while i < length and (text[i].isdigit() or text[i] == "."):
                    i += 1
                tokens.append(Token("NUMBER", text[start:i], start))
                continue

            if char.isalpha() or char in {"_", ".", "-", "/"}:
                start = i
                while i < length and (text[i].isalnum() or text[i] in {"_", ".", "-", "/", ":"}):
                    i += 1
                tokens.append(Token("WORD", text[start:i], start))
                continue

            if char == ",":
                tokens.append(Token("COMMA", char, i))
                i += 1
                continue

            raise ValueError(f"Unexpected character {char!r} at position {i}")

        tokens.append(Token("EOF", "", length))
        return tokens
