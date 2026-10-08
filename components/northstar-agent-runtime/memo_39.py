"""Memoized Optimal BST: memoization example.

Min expected search cost: try every key as root, adding the subtree frequency sum. The (i, j) cache gives O(n^3).

What this IS: a real memoized optimal-BST cost solver over an (i, j) cache.
What this IS NOT: a tree builder; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_39_VERSION = "memo-optimal-bst.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-optimal-bst.v1"


class MemoError(Exception):
    """Fail-closed."""


def optimal_bst(freq: tuple, i: int = 0, j: int | None = None, _cache: dict | None = None) -> int:
    """Memoized optimal BST cost for freq[i..j]."""
    if j is None:
        j = len(freq) - 1
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if i > j:
        cache[key] = 0
    elif i == j:
        cache[key] = freq[i]
    else:
        total = sum(freq[i:j + 1])
        cache[key] = min(
            optimal_bst(freq, i, k - 1, cache) + optimal_bst(freq, k + 1, j, cache) for k in range(i, j + 1)
        ) + total
    return cache[key]

def test_optimal_bst_example():
    assert optimal_bst((34, 8, 50)) == 142


def test_optimal_bst_single():
    assert optimal_bst((10,)) == 10


def test_optimal_bst_empty():
    assert optimal_bst(()) == 0

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
    test_optimal_bst_example()
    test_optimal_bst_single()
    test_optimal_bst_empty()
    assert stdlib_only()
    print("memo-39 OK: optimal-bst")


if __name__ == "__main__":
    main()
