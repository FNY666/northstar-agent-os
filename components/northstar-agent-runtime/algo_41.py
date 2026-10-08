"""Fibonacci numbers via dynamic programming.

Recurrence: F(0) = 0, F(1) = 1, F(n) = F(n-1) + F(n-2) for n >= 2.

* ``fib`` is iterative bottom-up: O(n) time, O(1) space.
* ``fib_memo`` is top-down with memoisation: O(n) time, O(n) space
  (memo table plus recursion depth).

Both raise ``ValueError`` for negative ``n``.
"""

import ast
import sys
from pathlib import Path

ALGO_41_VERSION = "algo-41.v1"

STDLIB_USED = frozenset({"ast", "pathlib", "sys"})


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every imported top-level module
    is one this module actually uses from the standard library."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    stdlib_names = set(sys.stdlib_module_names)
    for name in sorted(imported):
        assert name in stdlib_names, "non-stdlib import: %s" % name
        assert name in STDLIB_USED, "imported but unused module: %s" % name
    assert set(STDLIB_USED) == imported, (
        "import drift: declared %s vs found %s"
        % (sorted(STDLIB_USED), sorted(imported))
    )
    return True


def fib(n: int) -> int:
    """Iterative Fibonacci: F(0)=0, F(1)=1, F(n)=F(n-1)+F(n-2). O(n)/O(1)."""
    if n < 0:
        raise ValueError("n must be non-negative, got %r" % (n,))
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def fib_memo(n: int) -> int:
    """Top-down memoised Fibonacci. O(n) time, O(n) space."""
    if n < 0:
        raise ValueError("n must be non-negative, got %r" % (n,))
    memo = {0: 0, 1: 1}

    def rec(k: int) -> int:
        if k not in memo:
            memo[k] = rec(k - 1) + rec(k - 2)
        return memo[k]

    return rec(n)


def main() -> None:
    assert fib(0) == 0
    assert fib(1) == 1
    assert fib(10) == 55
    assert fib(20) == 6765
    assert fib_memo(10) == 55
    assert all(fib_memo(i) == fib(i) for i in range(30))
    for bad in (-1, -100):
        for fn in (fib, fib_memo):
            try:
                fn(bad)
            except ValueError:
                pass
            else:
                raise AssertionError("expected ValueError for n=%r" % (bad,))
    assert stdlib_only()
    print("algo-41 OK")


if __name__ == "__main__":
    main()
