"""Memoized Strange Printer: memoization example.

Fewest turns to print s: print s[r] alone (1 + rest), or merge with an equal earlier char. The (l, r) cache gives O(n^3).

What this IS: a real memoized strange-printer turn counter.
What this IS NOT: a print-sequence builder; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_44_VERSION = "memo-strange-printer.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-strange-printer.v1"


class MemoError(Exception):
    """Fail-closed."""


def strange_printer(s: str, l: int = 0, r: int | None = None, _cache: dict | None = None) -> int:
    """Memoized strange-printer min turns for s[l..r]."""
    if r is None:
        r = len(s) - 1
    cache: dict = _cache if _cache is not None else {}
    key = (l, r)
    if key in cache:
        return cache[key]
    if l > r:
        cache[key] = 0
    else:
        cache[key] = strange_printer(s, l, r - 1, cache) + 1
        for k in range(l, r):
            if s[k] == s[r]:
                cache[key] = min(
                    cache[key],
                    strange_printer(s, l, k, cache) + strange_printer(s, k + 1, r - 1, cache),
                )
    return cache[key]

def test_strange_printer_example():
    assert strange_printer("aaabbb") == 2


def test_strange_printer_single():
    assert strange_printer("a") == 1


def test_strange_printer_empty():
    assert strange_printer("") == 0

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_strange_printer_example()
    test_strange_printer_single()
    test_strange_printer_empty()
    assert stdlib_only()
    print("memo-44 OK: strange-printer")


if __name__ == "__main__":
    main()
