"""Gray to binary: invert the Gray encoding.

Repeatedly XORs the accumulating result with right-shifted copies until the shifts empty out.

What this IS: the exact inverse of bit_40.
What this IS NOT: a guess; the mapping is bijective and exact.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_41_VERSION = "bit-gray-to-binary.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-gray-to-binary.v1"


class BitError(Exception):
    """Fail-closed."""


def gray_to_binary(g: int) -> int:
    """Convert Gray code back to binary."""
    if g < 0:
        raise BitError("non-negative only")
    n = 0
    while g:
        n ^= g
        g >>= 1
    return n

def test_ungray_basic():
    assert gray_to_binary(4) == 7


def test_ungray_zero():
    assert gray_to_binary(0) == 0


def test_ungray_one():
    assert gray_to_binary(1) == 1


def test_ungray_roundtrip():
    for i in range(32):
        g = i ^ (i >> 1)
        assert gray_to_binary(g) == i

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
    test_ungray_basic()
    test_ungray_zero()
    test_ungray_one()
    test_ungray_roundtrip()
    assert stdlib_only()
    print("bit-41 OK: gray-to-binary")


if __name__ == "__main__":
    main()
