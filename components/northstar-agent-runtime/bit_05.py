"""Power of two test: n > 0 and exactly one bit set.

A power of two has a single 1-bit, so n & (n - 1) clears it to zero.

What this IS: the branchless one-bit test used by allocators.
What this IS NOT: a logarithm; it answers yes/no only.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_05_VERSION = "bit-power-of-two.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-power-of-two.v1"


class BitError(Exception):
    """Fail-closed."""


def is_power_of_two(n: int) -> bool:
    """True when n is a positive power of two."""
    return n > 0 and (n & (n - 1)) == 0

def test_pow2_true():
    assert is_power_of_two(1) is True
    assert is_power_of_two(16) is True


def test_pow2_zero():
    assert is_power_of_two(0) is False


def test_pow2_false():
    assert is_power_of_two(18) is False
    assert is_power_of_two(-4) is False

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
    test_pow2_true()
    test_pow2_zero()
    test_pow2_false()
    assert stdlib_only()
    print("bit-05 OK: power-of-two")


if __name__ == "__main__":
    main()
