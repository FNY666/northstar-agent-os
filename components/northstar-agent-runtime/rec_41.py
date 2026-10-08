"""McCarthy 91: nested double recursion

Returns 91 for all n <= 100 via nested self-application.

What this IS: a real McCarthy-91 nested recursion.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_41_VERSION = "rec-mccarthy91.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-mccarthy91.v1"


class RecError(Exception):
    """Fail-closed."""


def mc91(n: int) -> int:
    """McCarthy 91 function."""
    if n > 100:
        return n - 10
    return mc91(mc91(n + 11))

def test_mc91_below():
    assert mc91(99) == 91


def test_mc91_hundred():
    assert mc91(100) == 91


def test_mc91_above():
    assert mc91(101) == 91


def test_mc91_high():
    assert mc91(150) == 140

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
    test_mc91_below()
    test_mc91_hundred()
    test_mc91_above()
    test_mc91_high()
    assert stdlib_only()
    print("rec-mccarthy91 OK")


if __name__ == "__main__":
    main()
