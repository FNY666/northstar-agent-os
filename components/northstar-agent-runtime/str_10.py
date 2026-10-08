"""Edit distance: Levenshtein distance in O(min(m,n)) space.

Insert/delete/substitute cost 1; two-row DP.

What this IS: a real Levenshtein implementation.
What this IS NOT: Damerau transpositions; see str-25.
"""

from __future__ import annotations

import ast

#: Module version.
STR_10_VERSION = "str-edit-distance.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-edit-distance.v1"


class StrError(Exception):
    """Fail-closed."""


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance between a and b."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[len(b)]


def test_ed_classic():
    assert edit_distance("kitten", "sitting") == 3


def test_ed_empty():
    assert edit_distance("", "abc") == 3
    assert edit_distance("", "") == 0


def test_ed_same():
    assert edit_distance("abc", "abc") == 0


def test_ed_single():
    assert edit_distance("a", "b") == 1


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
    test_ed_classic()
    test_ed_empty()
    test_ed_same()
    test_ed_single()
    assert stdlib_only()
    print("str-10 OK: edit-distance")


if __name__ == "__main__":
    main()
