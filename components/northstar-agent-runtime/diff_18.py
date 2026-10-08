"""Max Value After Range Updates: difference array example.

Range adds via difference array; report the maximum value and its leftmost index after all updates.

What this IS: a real max-after-updates sweep, fail-closed on bad updates
What this IS NOT: materializing then calling max()
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_18_VERSION = "max-after-updates.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-max-after-updates.v1"


class DiffError(Exception):
    """Fail-closed."""


def max_after_updates(n: int, updates: list) -> tuple:
    """updates: list of (l, r, v). Returns (max_value, leftmost_index)."""
    if n <= 0:
        raise DiffError("n must be > 0")
    diff = [0] * (n + 1)
    for l, r, v in updates:
        if not (0 <= l <= r < n):
            raise DiffError("bad update")
        diff[l] += v
        diff[r + 1] -= v
    cur = 0
    best = None
    best_i = 0
    for i in range(n):
        cur += diff[i]
        if best is None or cur > best:
            best = cur
            best_i = i
    return best, best_i

def test_basic():
    assert max_after_updates(5, [(0, 4, 1), (2, 3, 5)]) == (6, 2)


def test_leftmost():
    assert max_after_updates(4, [(0, 3, 2)]) == (2, 0)


def test_no_updates():
    assert max_after_updates(3, []) == (0, 0)


def test_bad():
    try:
        max_after_updates(3, [(1, 5, 1)])
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
    test_leftmost()
    test_no_updates()
    test_bad()
    assert stdlib_only()
    print("diff-18 OK: max-after-updates")


if __name__ == "__main__":
    main()
