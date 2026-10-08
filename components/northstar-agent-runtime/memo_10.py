"""Memoized Binomial Coefficient: memoization example.

Pascal recurrence C(n,k) = C(n-1,k-1) + C(n-1,k). The (n, k) cache turns the exponential recursion into O(n*k).

What this IS: a real memoized binomial coefficient, fail-closed on negative n/k or k > n.
What this IS NOT: a multiplicative closed form; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_10_VERSION = "memo-binomial.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-binomial.v1"


class MemoError(Exception):
    """Fail-closed."""


def binom(n: int, k: int, _cache: dict | None = None) -> int:
    """Memoized binomial coefficient. Fail-closed on n < 0, k < 0, or k > n."""
    if n < 0 or k < 0 or k > n:
        raise MemoError("binom needs 0 <= k <= n")
    cache: dict = _cache if _cache is not None else {}
    key = (n, k)
    if key in cache:
        return cache[key]
    if k == 0 or k == n:
        cache[key] = 1
    else:
        cache[key] = binom(n - 1, k - 1, cache) + binom(n - 1, k, cache)
    return cache[key]

def test_binom_example():
    assert binom(10, 3) == 120


def test_binom_edges():
    assert binom(5, 0) == 1
    assert binom(5, 5) == 1


def test_binom_invalid_raises():
    try:
        binom(3, 5)
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
    test_binom_example()
    test_binom_edges()
    test_binom_invalid_raises()
    assert stdlib_only()
    print("memo-10 OK: binomial")


if __name__ == "__main__":
    main()
