"""Even test: parity of the lowest bit.

The units bit decides evenness for two's complement integers of any sign.

What this IS: the one-instruction evenness check.
What this IS NOT: a divisibility test; it only answers mod 2.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_34_VERSION = "bit-is-even.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-is-even.v1"


class BitError(Exception):
    """Fail-closed."""


def is_even(n: int) -> bool:
    """True when n is even (works for negatives too)."""
    return (n & 1) == 0

def test_even_true():
    assert is_even(4) is True


def test_even_false():
    assert is_even(7) is False


def test_even_zero():
    assert is_even(0) is True


def test_even_negative():
    assert is_even(-2) is True

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
    test_even_true()
    test_even_false()
    test_even_zero()
    test_even_negative()
    assert stdlib_only()
    print("bit-34 OK: is-even")


if __name__ == "__main__":
    main()
