"""Memoized Integer Break: memoization example.

Max product from breaking n into integers >= 2 parts: try every first cut, either stopping or breaking further. The cache gives O(n^2).

What this IS: a real memoized integer-break maximizer, fail-closed on n < 2.
What this IS NOT: a break reconstructor; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_27_VERSION = "memo-integer-break.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-integer-break.v1"


class MemoError(Exception):
    """Fail-closed."""


def int_break(n: int, _cache: dict | None = None) -> int:
    """Memoized integer-break max product. Fail-closed on n < 2."""
    if n < 2:
        raise MemoError("int_break needs n >= 2")
    cache: dict = _cache if _cache is not None else {}
    if n in cache:
        return cache[n]
    if n == 2:
        cache[n] = 1
    else:
        options = []
        for i in range(1, n):
            options.append(i * (n - i))
            if n - i >= 2:
                options.append(i * int_break(n - i, cache))
        cache[n] = max(options)
    return cache[n]

def test_int_break_10():
    assert int_break(10) == 36


def test_int_break_2():
    assert int_break(2) == 1


def test_int_break_small_raises():
    try:
        int_break(1)
    except MemoError:
        return
    raise AssertionError("expected MemoError")

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
    test_int_break_10()
    test_int_break_2()
    test_int_break_small_raises()
    assert stdlib_only()
    print("memo-27 OK: integer-break")


if __name__ == "__main__":
    main()
