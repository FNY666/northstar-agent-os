"""List palindrome: compare ends, recurse inside

Peels one element off each end per call.

What this IS: a real recursive list palindrome predicate.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_47_VERSION = "rec-list-pal.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-list-pal.v1"


class RecError(Exception):
    """Fail-closed."""


def is_list_pal(xs) -> bool:
    """True when the list reads the same backwards."""
    if len(xs) <= 1:
        return True
    return xs[0] == xs[-1] and is_list_pal(xs[1:-1])

def test_list_pal_true():
    assert is_list_pal([1, 2, 3, 2, 1]) is True


def test_list_pal_false():
    assert is_list_pal([1, 2, 3]) is False


def test_list_pal_empty():
    assert is_list_pal([]) is True


def test_list_pal_single():
    assert is_list_pal([7]) is True

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
    test_list_pal_true()
    test_list_pal_false()
    test_list_pal_empty()
    test_list_pal_single()
    assert stdlib_only()
    print("rec-list-pal OK")


if __name__ == "__main__":
    main()
