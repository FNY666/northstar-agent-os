"""Shifting Letters I: difference array example.

LeetCode 848: shifts[i] shifts the first i+1 letters forward; the cumulative effect is a difference array with range [0, i].

What this IS: real cumulative prefix shifts via difference array, fail-closed on bad input
What this IS NOT: recomputing the suffix sum per character
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_10_VERSION = "shifting-letters.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-shifting-letters.v1"


class DiffError(Exception):
    """Fail-closed."""


def shifting_letters(s: str, shifts: list) -> str:
    """shifts[i] shifts s[0..i] forward by shifts[i]."""
    n = len(s)
    if len(shifts) != n:
        raise DiffError("shifts length must match s")
    diff = [0] * (n + 1)
    for i, v in enumerate(shifts):
        if v < 0:
            raise DiffError("shifts must be >= 0")
        diff[0] += v
        diff[i + 1] -= v
    out = []
    cur = 0
    for i, ch in enumerate(s):
        cur += diff[i]
        out.append(chr((ord(ch) - 97 + cur) % 26 + 97))
    return "".join(out)

def test_example():
    assert shifting_letters("abc", [3, 5, 9]) == "rpl"


def test_second():
    assert shifting_letters("aaa", [1, 2, 3]) == "gfd"


def test_zero_shifts():
    assert shifting_letters("xyz", [0, 0, 0]) == "xyz"


def test_bad():
    for bad in (lambda: shifting_letters("ab", [1]),
                lambda: shifting_letters("ab", [1, -1])):
        try:
            bad()
        except DiffError:
            continue
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
    test_second()
    test_zero_shifts()
    test_bad()
    assert stdlib_only()
    print("diff-10 OK: shifting-letters")


if __name__ == "__main__":
    main()
