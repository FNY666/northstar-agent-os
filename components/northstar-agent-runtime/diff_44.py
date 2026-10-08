"""Union Length Of Intervals: difference array example.

Total length covered by [l, r) half-open intervals: sweep the sparse difference map, accumulating only while coverage is positive.

What this IS: a real union-length sweep, fail-closed on bad intervals
What this IS NOT: summing interval lengths with double counting
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_44_VERSION = "union-length.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-union-length.v1"


class DiffError(Exception):
    """Fail-closed."""


def union_length(intervals: list) -> int:
    """intervals: list of (l, r) half-open. Returns total covered length."""
    if not intervals:
        return 0
    d = {}
    for l, r in intervals:
        if not (l < r):
            raise DiffError("need l < r")
        d[l] = d.get(l, 0) + 1
        d[r] = d.get(r, 0) - 1
    cur = 0
    total = 0
    prev = None
    for k in sorted(d):
        if prev is not None and cur > 0:
            total += k - prev
        cur += d[k]
        prev = k
    return total

def test_example():
    assert union_length([[1, 3], [2, 6], [8, 10], [15, 18]]) == 10


def test_nested():
    assert union_length([[1, 5], [2, 3]]) == 4


def test_empty():
    assert union_length([]) == 0


def test_bad():
    try:
        union_length([[5, 5]])
    except DiffError:
        return
    raise AssertionError("expected DiffError")

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
    test_example()
    test_nested()
    test_empty()
    test_bad()
    assert stdlib_only()
    print("diff-44 OK: union-length")


if __name__ == "__main__":
    main()
