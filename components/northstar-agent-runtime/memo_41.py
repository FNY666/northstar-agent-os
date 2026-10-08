"""Memoized Matrix Chain Multiplication: memoization example.

Min scalar multiplications: try every split k, adding dims[i-1]*dims[k]*dims[j]. The (i, j) cache gives O(n^3).

What this IS: a real memoized matrix-chain cost solver over 1-based matrix indices.
What this IS NOT: a parenthesization builder; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_41_VERSION = "memo-matrix-chain.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-matrix-chain.v1"


class MemoError(Exception):
    """Fail-closed."""


def matrix_chain(dims: tuple, i: int = 1, j: int | None = None, _cache: dict | None = None) -> int:
    """Memoized matrix-chain min cost for matrices i..j (1-based)."""
    if j is None:
        j = len(dims) - 1
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if i == j:
        cache[key] = 0
    else:
        cache[key] = min(
            matrix_chain(dims, i, k, cache)
            + matrix_chain(dims, k + 1, j, cache)
            + dims[i - 1] * dims[k] * dims[j]
            for k in range(i, j)
        )
    return cache[key]

def test_matrix_chain_example():
    assert matrix_chain((1, 2, 3, 4)) == 18


def test_matrix_chain_single():
    assert matrix_chain((2, 3)) == 0


def test_matrix_chain_two():
    assert matrix_chain((2, 3, 4)) == 24

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
    test_matrix_chain_example()
    test_matrix_chain_single()
    test_matrix_chain_two()
    assert stdlib_only()
    print("memo-41 OK: matrix-chain")


if __name__ == "__main__":
    main()
