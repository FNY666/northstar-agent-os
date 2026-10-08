"""Binary to Gray code: n ^ (n >> 1).

Each Gray bit is the XOR of two adjacent binary bits, so one binary change flips one Gray bit.

What this IS: the encoder for single-change counters.
What this IS NOT: a compression; width is unchanged.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_40_VERSION = "bit-binary-to-gray.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-binary-to-gray.v1"


class BitError(Exception):
    """Fail-closed."""


def binary_to_gray(n: int) -> int:
    """Convert binary to Gray code."""
    if n < 0:
        raise BitError("non-negative only")
    return n ^ (n >> 1)

def test_gray_basic():
    assert binary_to_gray(7) == 4  # 111 -> 100


def test_gray_zero():
    assert binary_to_gray(0) == 0


def test_gray_one():
    assert binary_to_gray(1) == 1


def test_gray_two():
    assert binary_to_gray(2) == 3  # 10 -> 11


def test_gray_ten():
    assert binary_to_gray(10) == 15  # 1010 -> 1111

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
    test_gray_basic()
    test_gray_zero()
    test_gray_one()
    test_gray_two()
    test_gray_ten()
    assert stdlib_only()
    print("bit-40 OK: binary-to-gray")


if __name__ == "__main__":
    main()
