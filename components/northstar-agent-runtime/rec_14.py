"""Fast exponentiation: b^e by squaring

Halves the exponent each call; O(log e) multiplications.

What this IS: a real recursive power by squaring, fail-closed on negative exponents.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_14_VERSION = "rec-rpow.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-rpow.v1"


class RecError(Exception):
    """Fail-closed."""


def rpow(b, e: int):
    """b**e. Fail-closed on negative e."""
    if e < 0:
        raise RecError("rpow needs e >= 0")
    if e == 0:
        return 1
    h = rpow(b, e // 2)
    return h * h * (b if e % 2 else 1)

def test_rpow_zero():
    assert rpow(5, 0) == 1


def test_rpow_basic():
    assert rpow(2, 10) == 1024


def test_rpow_odd():
    assert rpow(3, 3) == 27


def test_rpow_negative_raises():
    try:
        rpow(2, -1)
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
    test_rpow_zero()
    test_rpow_basic()
    test_rpow_odd()
    test_rpow_negative_raises()
    assert stdlib_only()
    print("rec-rpow OK")


if __name__ == "__main__":
    main()
