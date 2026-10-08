"""Memoized Decode Ways: memoization example.

Count decodings of a digit string: a valid 1-digit or 2-digit (10-26) prefix extends the count. The index cache gives O(n).

What this IS: a real memoized decode counter, treating leading zeros as dead ends.
What this IS NOT: an actual decoder producing strings; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_15_VERSION = "memo-decode-ways.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-decode-ways.v1"


class MemoError(Exception):
    """Fail-closed."""


def decode_ways(s: str, i: int = 0, _cache: dict | None = None) -> int:
    """Memoized decode-way counter."""
    cache: dict = _cache if _cache is not None else {}
    if i in cache:
        return cache[i]
    if i == len(s):
        cache[i] = 1
    elif s[i] == "0":
        cache[i] = 0
    else:
        total = decode_ways(s, i + 1, cache)
        if i + 1 < len(s) and 10 <= int(s[i:i + 2]) <= 26:
            total += decode_ways(s, i + 2, cache)
        cache[i] = total
    return cache[i]

def test_decode_ways_example():
    assert decode_ways("226") == 3


def test_decode_ways_zero():
    assert decode_ways("06") == 0


def test_decode_ways_simple():
    assert decode_ways("12") == 2

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
    test_decode_ways_example()
    test_decode_ways_zero()
    test_decode_ways_simple()
    assert stdlib_only()
    print("memo-15 OK: decode-ways")


if __name__ == "__main__":
    main()
