"""Booth's minimal rotation: lexicographically smallest rotation in O(n).

Modified KMP failure comparison on s+s without building failure tables.

What this IS: a real O(n) Booth implementation.
What this IS NOT: maximal rotation (symmetric variant).
"""

from __future__ import annotations

import ast

#: Module version.
STR_29_VERSION = "str-booth.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-booth-min-rotation.v1"


class StrError(Exception):
    """Fail-closed."""


def booth_min_rotation(s: str) -> str:
    """Return the lexicographically smallest rotation of s."""
    if not s:
        return ""
    s2 = s + s
    n = len(s)
    i, j, k = 0, 1, 0
    while i < n and j < n and k < n:
        a, b = s2[i + k], s2[j + k]
        if a == b:
            k += 1
            continue
        if a > b:
            i = i + k + 1
        else:
            j = j + k + 1
        if i == j:
            j += 1
        k = 0
    start = min(i, j)
    return s2[start:start + n]


def test_booth_known():
    assert booth_min_rotation("bbaaccaadd") == "aaccaaddbb"


def test_booth_sorted():
    assert booth_min_rotation("abc") == "abc"


def test_booth_empty():
    assert booth_min_rotation("") == ""


def test_booth_single():
    assert booth_min_rotation("z") == "z"


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
    test_booth_known()
    test_booth_sorted()
    test_booth_empty()
    test_booth_single()
    assert stdlib_only()
    print("str-29 OK: booth")


if __name__ == "__main__":
    main()
