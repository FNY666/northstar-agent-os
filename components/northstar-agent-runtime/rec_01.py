"""Factorial: n! by direct recursion

Base cases 0 and 1 return 1; each call multiplies n by fact(n-1). Depth is O(n).

What this IS: a real recursive factorial, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_01_VERSION = "rec-factorial.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-factorial.v1"


class RecError(Exception):
    """Fail-closed."""


def fact(n: int) -> int:
    """n! Fail-closed on negatives."""
    if n < 0:
        raise RecError("fact needs n >= 0")
    if n <= 1:
        return 1
    return n * fact(n - 1)

def test_fact_zero():
    assert fact(0) == 1


def test_fact_five():
    assert fact(5) == 120


def test_fact_ten():
    assert fact(10) == 3628800


def test_fact_negative_raises():
    try:
        fact(-1)
    except RecError:
        return
    raise AssertionError("expected RecError")

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
    test_fact_zero()
    test_fact_five()
    test_fact_ten()
    test_fact_negative_raises()
    assert stdlib_only()
    print("rec-factorial OK")


if __name__ == "__main__":
    main()
