"""Array Manipulation Max: difference array example.

HackerRank-style: n positions, queries (a, b, k) 1-indexed inclusive; report the maximum value after all operations.

What this IS: the real O(n+q) sweep for max-after-range-adds, fail-closed on bad queries
What this IS NOT: a simulation that applies each query elementwise
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_03_VERSION = "array-manipulation.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-array-manipulation.v1"


class DiffError(Exception):
    """Fail-closed."""


def array_manipulation(n: int, queries: list) -> int:
    """queries: list of (a, b, k), 1-indexed inclusive. Returns max value."""
    if n <= 0:
        raise DiffError("n must be > 0")
    diff = [0] * (n + 2)
    for a, b, k in queries:
        if not (1 <= a <= b <= n):
            raise DiffError("queries must satisfy 1 <= a <= b <= n")
        diff[a] += k
        diff[b + 1] -= k
    cur = 0
    best = 0
    for i in range(1, n + 1):
        cur += diff[i]
        if cur > best:
            best = cur
    return best

def test_hackerrank_example():
    assert array_manipulation(10, [(1, 5, 3), (4, 8, 7), (6, 9, 1)]) == 10


def test_second():
    assert array_manipulation(5, [(1, 2, 100), (2, 5, 100), (3, 4, 100)]) == 200


def test_no_queries():
    assert array_manipulation(4, []) == 0


def test_bad_query():
    try:
        array_manipulation(5, [(2, 6, 1)])
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
    test_hackerrank_example()
    test_second()
    test_no_queries()
    test_bad_query()
    assert stdlib_only()
    print("diff-03 OK: array-manipulation")


if __name__ == "__main__":
    main()
