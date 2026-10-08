"""Binary rendering: bits of n//2 then n%2

Recurses on the quotient and appends the remainder bit.

What this IS: a real recursive binary string renderer, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_24_VERSION = "rec-to-binary.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-to-binary.v1"


class RecError(Exception):
    """Fail-closed."""


def to_binary(n: int) -> str:
    """Binary string of n. Fail-closed on negatives."""
    if n < 0:
        raise RecError("to_binary needs n >= 0")
    if n < 2:
        return str(n)
    return to_binary(n // 2) + str(n % 2)

def test_to_binary_basic():
    assert to_binary(13) == "1101"


def test_to_binary_zero():
    assert to_binary(0) == "0"


def test_to_binary_one():
    assert to_binary(1) == "1"


def test_to_binary_negative_raises():
    try:
        to_binary(-2)
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
    test_to_binary_basic()
    test_to_binary_zero()
    test_to_binary_one()
    test_to_binary_negative_raises()
    assert stdlib_only()
    print("rec-to-binary OK")


if __name__ == "__main__":
    main()
