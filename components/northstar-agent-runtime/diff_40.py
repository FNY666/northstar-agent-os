"""Leftmost Argmax After Adds: difference array example.

After range adds, the leftmost index holding the maximum value, plus the value itself.

What this IS: a real leftmost-argmax sweep, fail-closed on bad input
What this IS NOT: returning any max index
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_40_VERSION = "argmax-leftmost.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-argmax-leftmost.v1"


class DiffError(Exception):
    """Fail-closed."""


def argmax_leftmost(n: int, updates: list) -> tuple:
    """updates: list of (l, r, v). Returns (index, value) of leftmost max."""
    if n <= 0:
        raise DiffError("n must be > 0")
    d = [0] * (n + 1)
    for l, r, v in updates:
        if not (0 <= l <= r < n):
            raise DiffError("bad update")
        d[l] += v
        d[r + 1] -= v
    cur = 0
    best = None
    bi = 0
    for i in range(n):
        cur += d[i]
        if best is None or cur > best:
            best = cur
            bi = i
    return bi, best

def test_basic():
    assert argmax_leftmost(4, [(0, 3, 2), (1, 2, 3)]) == (1, 5)


def test_leftmost_tie():
    assert argmax_leftmost(4, [(0, 3, 2)]) == (0, 2)


def test_no_updates():
    assert argmax_leftmost(3, []) == (0, 0)


def test_bad():
    try:
        argmax_leftmost(3, [(2, 5, 1)])
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
    test_leftmost_tie()
    test_no_updates()
    test_bad()
    assert stdlib_only()
    print("diff-40 OK: argmax-leftmost")


if __name__ == "__main__":
    main()
