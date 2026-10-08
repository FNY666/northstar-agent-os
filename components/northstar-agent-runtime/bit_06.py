"""All-ones test: detect n of the form 2^k - 1.

Adding one to an all-ones value carries through every bit, so n & (n + 1) is zero.

What this IS: the mask-validity check used before complement tricks.
What this IS NOT: a popcount; it only recognizes the all-ones shape.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_06_VERSION = "bit-all-ones.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-all-ones.v1"


class BitError(Exception):
    """Fail-closed."""


def is_all_ones(n: int) -> bool:
    """True when n is of the form 2^k - 1 (binary all ones)."""
    return n > 0 and (n & (n + 1)) == 0

def test_all_ones_true():
    assert is_all_ones(7) is True
    assert is_all_ones(1) is True


def test_all_ones_false():
    assert is_all_ones(8) is False


def test_all_ones_zero():
    assert is_all_ones(0) is False

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
    test_all_ones_true()
    test_all_ones_false()
    test_all_ones_zero()
    assert stdlib_only()
    print("bit-06 OK: all-ones")


if __name__ == "__main__":
    main()
