"""Shifting Letters II: difference array example.

LeetCode 2381: shifts (start, end, direction) with direction 1 = forward, 0 = backward; applied via a signed difference array.

What this IS: real signed range shifts on a string via difference array, fail-closed on bad input
What this IS NOT: shifting each character one query at a time
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_09_VERSION = "shifting-letters-ii.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-shifting-letters-ii.v1"


class DiffError(Exception):
    """Fail-closed."""


def shifting_letters_ii(s: str, shifts: list) -> str:
    """shifts: list of (start, end, direction); direction in (0, 1)."""
    n = len(s)
    diff = [0] * (n + 1)
    for l, r, d in shifts:
        if not (0 <= l <= r < n) or d not in (0, 1):
            raise DiffError("bad shift")
        delta = 1 if d == 1 else -1
        diff[l] += delta
        diff[r + 1] -= delta
    out = []
    cur = 0
    for i, ch in enumerate(s):
        cur += diff[i]
        out.append(chr((ord(ch) - 97 + cur) % 26 + 97))
    return "".join(out)

def test_example():
    assert shifting_letters_ii("abc", [[0, 1, 0], [1, 2, 1]]) == "zbd"


def test_leetcode():
    assert shifting_letters_ii("dztz", [[0, 0, 0], [1, 1, 1]]) == "catz"


def test_no_shifts():
    assert shifting_letters_ii("hello", []) == "hello"


def test_bad_shift():
    try:
        shifting_letters_ii("abc", [[0, 2, 2]])
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
    test_example()
    test_leetcode()
    test_no_shifts()
    test_bad_shift()
    assert stdlib_only()
    print("diff-09 OK: shifting-letters-ii")


if __name__ == "__main__":
    main()
