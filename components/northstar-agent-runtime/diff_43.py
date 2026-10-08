"""Count Above Threshold: difference array example.

After range adds, count positions whose value strictly exceeds t.

What this IS: a real count-over-threshold sweep, fail-closed on bad updates
What this IS NOT: counting without materializing
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_43_VERSION = "count-above-threshold.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-count-above-threshold.v1"


class DiffError(Exception):
    """Fail-closed."""


def count_above_threshold(n: int, updates: list, t: int) -> int:
    """updates: list of (l, r, v). Counts indices with value > t."""
    if n <= 0:
        raise DiffError("n must be > 0")
    d = [0] * (n + 1)
    for l, r, v in updates:
        if not (0 <= l <= r < n):
            raise DiffError("bad update")
        d[l] += v
        d[r + 1] -= v
    cur = 0
    cnt = 0
    for i in range(n):
        cur += d[i]
        if cur > t:
            cnt += 1
    return cnt

def test_basic():
    assert count_above_threshold(5, [(0, 4, 3), (1, 3, 2)], 4) == 3


def test_none():
    assert count_above_threshold(5, [(0, 4, 3)], 10) == 0


def test_all():
    assert count_above_threshold(3, [(0, 2, 5)], 4) == 3


def test_bad():
    try:
        count_above_threshold(3, [(0, 3, 1)], 0)
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
    test_basic()
    test_none()
    test_all()
    test_bad()
    assert stdlib_only()
    print("diff-43 OK: count-above-threshold")


if __name__ == "__main__":
    main()
