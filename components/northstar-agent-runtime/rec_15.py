"""Euclid GCD: gcd(a,b) = gcd(b, a mod b)

Each call strictly shrinks the arguments; terminates by the division algorithm.

What this IS: a real recursive Euclid GCD, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_15_VERSION = "rec-gcd.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-gcd.v1"


class RecError(Exception):
    """Fail-closed."""


def gcd(a: int, b: int) -> int:
    """Greatest common divisor. Fail-closed on negatives."""
    if a < 0 or b < 0:
        raise RecError("gcd needs non-negative inputs")
    if b == 0:
        return a
    return gcd(b, a % b)

def test_gcd_basic():
    assert gcd(48, 18) == 6


def test_gcd_coprime():
    assert gcd(17, 5) == 1


def test_gcd_zero():
    assert gcd(7, 0) == 7


def test_gcd_negative_raises():
    try:
        gcd(-1, 5)
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
    test_gcd_basic()
    test_gcd_coprime()
    test_gcd_zero()
    test_gcd_negative_raises()
    assert stdlib_only()
    print("rec-gcd OK")


if __name__ == "__main__":
    main()
