"""Mutual-recursion parity: even calls odd and back

Two functions calling each other; depth is O(n).

What this IS: a real mutual-recursion parity pair, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_48_VERSION = "rec-mutual-parity.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-mutual-parity.v1"


class RecError(Exception):
    """Fail-closed."""


def is_even(n: int) -> bool:
    """True when n is even. Fail-closed on negatives."""
    if n < 0:
        raise RecError("parity needs n >= 0")
    if n == 0:
        return True
    return is_odd(n - 1)


def is_odd(n: int) -> bool:
    """True when n is odd. Fail-closed on negatives."""
    if n < 0:
        raise RecError("parity needs n >= 0")
    if n == 0:
        return False
    return is_even(n - 1)

def test_even_true():
    assert is_even(4) is True


def test_odd_true():
    assert is_odd(7) is True


def test_even_zero():
    assert is_even(0) is True


def test_parity_negative_raises():
    try:
        is_even(-1)
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
    test_even_true()
    test_odd_true()
    test_even_zero()
    test_parity_negative_raises()
    assert stdlib_only()
    print("rec-mutual-parity OK")


if __name__ == "__main__":
    main()
