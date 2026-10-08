"""Backtracking: Brace expansion -- expand an expression with (possibly nested)
braces into all represented strings.

IS: a simplified mock of shell brace expansion: {a,b} alternatives,
concatenation of adjacent terms, and nested braces (e.g. a{b,c{d,e}}f).
IS NOT: full bash brace semantics -- no numeric/alpha ranges ({1..5}),
no empty alternatives trimming, no globbing/escaping rules.
"""

from __future__ import annotations

VERSION = "backtrack_48.v1"


import ast
from typing import List, Tuple

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def expand(expression: str) -> List[str]:
    """Expand a brace expression into the list of represented strings."""

    def parse_expr(pos: int) -> Tuple[List[str], int]:
        # Parse a concatenated sequence until '}', ',' or end of input.
        parts = [""]
        while pos < len(expression) and expression[pos] not in ("}", ","):
            if expression[pos] == "{":
                group, pos = parse_group(pos + 1)
                parts = [p + g for p in parts for g in group]
            else:
                parts = [p + expression[pos] for p in parts]
                pos += 1
        return parts, pos

    def parse_group(pos: int) -> Tuple[List[str], int]:
        # Parse comma-separated alternatives until the closing '}'.
        options: List[str] = []
        while True:
            option, pos = parse_expr(pos)
            options.extend(option)
            if pos < len(expression) and expression[pos] == ",":
                pos += 1
                continue
            return options, pos + 1  # skip '}'

    result, _ = parse_expr(0)
    return result


def stdlib_only() -> bool:
    """Return True only if every import in this file comes from the allowed stdlib set."""
    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.module.split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert sorted(expand("{a,b}c{d,e}f")) == ["acdf", "acef", "bcdf", "bcef"]
    assert expand("abcd") == ["abcd"]
    assert sorted(expand("{a,b}{c,d}")) == ["ac", "ad", "bc", "bd"]
    assert sorted(expand("a{b,c{d,e}}f")) == ["abf", "acdf", "acef"]
    assert expand("{x}") == ["x"]
    assert expand("") == [""]
    print("backtrack_48 OK")


if __name__ == "__main__":
    main()
