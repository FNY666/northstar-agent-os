"""Memoized Unique Paths: memoization example.

Grid paths moving only right/down: paths(i,j) = paths(i+1,j) + paths(i,j+1). The (i, j) cache gives O(m*n).

What this IS: a real memoized grid-path counter, fail-closed on non-positive dimensions.
What this IS NOT: an obstacle-grid variant; the host picks the problem shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_14_VERSION = "memo-unique-paths.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-unique-paths.v1"


class MemoError(Exception):
    """Fail-closed."""


def unique_paths(m: int, n: int, i: int = 0, j: int = 0, _cache: dict | None = None) -> int:
    """Memoized unique-path count. Fail-closed on m <= 0 or n <= 0."""
    if m <= 0 or n <= 0:
        raise MemoError("unique_paths needs m > 0 and n > 0")
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if i == m - 1 and j == n - 1:
        cache[key] = 1
    else:
        down = unique_paths(m, n, i + 1, j, cache) if i + 1 < m else 0
        right = unique_paths(m, n, i, j + 1, cache) if j + 1 < n else 0
        cache[key] = down + right
    return cache[key]

def test_unique_paths_example():
    assert unique_paths(3, 7) == 28


def test_unique_paths_single():
    assert unique_paths(1, 1) == 1


def test_unique_paths_invalid_raises():
    try:
        unique_paths(0, 5)
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
    test_unique_paths_example()
    test_unique_paths_single()
    test_unique_paths_invalid_raises()
    assert stdlib_only()
    print("memo-14 OK: unique-paths")


if __name__ == "__main__":
    main()
