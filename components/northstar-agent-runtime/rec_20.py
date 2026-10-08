"""Palindrome check: compare outer pair, recurse inside

Peels one character off each end per call; O(n) time.

What this IS: a real recursive palindrome predicate.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_20_VERSION = "rec-is-pal.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-is-pal.v1"


class RecError(Exception):
    """Fail-closed."""


def is_pal(s: str) -> bool:
    """True when s reads the same backwards."""
    if len(s) <= 1:
        return True
    return s[0] == s[-1] and is_pal(s[1:-1])

def test_pal_true():
    assert is_pal("racecar") is True


def test_pal_false():
    assert is_pal("hello") is False


def test_pal_empty():
    assert is_pal("") is True


def test_pal_single():
    assert is_pal("a") is True

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_pal_true()
    test_pal_false()
    test_pal_empty()
    test_pal_single()
    assert stdlib_only()
    print("rec-is-pal OK")


if __name__ == "__main__":
    main()
