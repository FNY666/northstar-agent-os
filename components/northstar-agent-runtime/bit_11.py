"""Even parity: true when the popcount is even.

Folds the parity bit once per cleared 1-bit; even counts fold back to zero.

What this IS: the single-bit error-detection primitive.
What this IS NOT: a checksum; it detects only odd numbers of flips.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_11_VERSION = "bit-parity-even.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-parity-even.v1"


class BitError(Exception):
    """Fail-closed."""


def parity_even(n: int) -> bool:
    """True when n has an even number of set bits."""
    if n < 0:
        raise BitError("non-negative only")
    p = 0
    while n:
        p ^= 1
        n &= n - 1
    return p == 0

def test_parity_even_true():
    assert parity_even(3) is True  # 0b11


def test_parity_even_false():
    assert parity_even(7) is False  # 0b111


def test_parity_zero():
    assert parity_even(0) is True

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
    test_parity_even_true()
    test_parity_even_false()
    test_parity_zero()
    assert stdlib_only()
    print("bit-11 OK: parity-even")


if __name__ == "__main__":
    main()
