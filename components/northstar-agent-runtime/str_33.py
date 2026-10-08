"""Isomorphic strings: bijective character mapping test.

Two maps enforce a bijection between the alphabets.

What this IS: a real O(n) check.
What this IS NOT: pattern-word matching variants.
"""

from __future__ import annotations

import ast

#: Module version.
STR_33_VERSION = "str-isomorphic.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-isomorphic-strings.v1"


class StrError(Exception):
    """Fail-closed."""


def is_isomorphic(a: str, b: str) -> bool:
    """True iff chars of a map bijectively onto chars of b."""
    if len(a) != len(b):
        return False
    ma, mb = {}, {}
    for x, y in zip(a, b):
        if ma.get(x, y) != y or mb.get(y, x) != x:
            return False
        ma[x] = y
        mb[y] = x
    return True


def test_iso_true():
    assert is_isomorphic("egg", "add") is True
    assert is_isomorphic("paper", "title") is True


def test_iso_false():
    assert is_isomorphic("foo", "bar") is False


def test_iso_length():
    assert is_isomorphic("ab", "a") is False


def test_iso_empty():
    assert is_isomorphic("", "") is True


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
    test_iso_true()
    test_iso_false()
    test_iso_length()
    test_iso_empty()
    assert stdlib_only()
    print("str-33 OK: isomorphic")


if __name__ == "__main__":
    main()
