"""Power of four test: single bit in an even position.

A power of four is a power of two whose lone 1-bit sits at an even index, so it never hits the 0xAAAAAAAA mask.

What this IS: the positional refinement of the power-of-two test.
What this IS NOT: a root extractor; it answers yes/no only.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_48_VERSION = "bit-power-of-four.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-power-of-four.v1"


class BitError(Exception):
    """Fail-closed."""


def is_power_of_four(n: int) -> bool:
    """Power of two with the single bit in an even position."""
    return n > 0 and (n & (n - 1)) == 0 and (n & 0xAAAAAAAA) == 0

def test_p4_true():
    assert is_power_of_four(1) is True
    assert is_power_of_four(16) is True
    assert is_power_of_four(64) is True


def test_p4_false():
    assert is_power_of_four(8) is False
    assert is_power_of_four(2) is False


def test_p4_zero():
    assert is_power_of_four(0) is False

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
    test_p4_true()
    test_p4_false()
    test_p4_zero()
    assert stdlib_only()
    print("bit-48 OK: power-of-four")


if __name__ == "__main__":
    main()
