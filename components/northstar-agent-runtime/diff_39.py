"""First Index At Least K: difference array example.

After range adds, find the first index whose value reaches k; -1 when no index qualifies.

What this IS: a real linear scan over the materialized prefix, fail-closed on bad input
What this IS NOT: a binary search that assumes monotonicity
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_39_VERSION = "first-ge-k.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-first-ge-k.v1"


class DiffError(Exception):
    """Fail-closed."""


def first_ge_k(n: int, updates: list, k: int) -> int:
    """updates: list of (l, r, v). First index with value >= k, else -1."""
    if n <= 0:
        raise DiffError("n must be > 0")
    d = [0] * (n + 1)
    for l, r, v in updates:
        if not (0 <= l <= r < n):
            raise DiffError("bad update")
        d[l] += v
        d[r + 1] -= v
    cur = 0
    for i in range(n):
        cur += d[i]
        if cur >= k:
            return i
    return -1

def test_found():
    assert first_ge_k(5, [(0, 4, 3), (2, 2, 5)], 8) == 2


def test_first():
    assert first_ge_k(4, [(0, 3, 10)], 5) == 0


def test_not_found():
    assert first_ge_k(5, [(0, 4, 3)], 100) == -1


def test_bad():
    try:
        first_ge_k(3, [(0, 5, 1)], 1)
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
    test_found()
    test_first()
    test_not_found()
    test_bad()
    assert stdlib_only()
    print("diff-39 OK: first-ge-k")


if __name__ == "__main__":
    main()
