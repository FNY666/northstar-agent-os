"""Previous power of two: largest 2^k <= n.

The bit-length locates the top 1-bit; rebuilding it floors to the power of two.

What this IS: the floor counterpart to bit_38.
What this IS NOT: a logarithm; it returns the power itself.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_39_VERSION = "bit-prev-power-of-two.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-prev-power-of-two.v1"


class BitError(Exception):
    """Fail-closed."""


def prev_power_of_two(n: int) -> int:
    """Largest power of two <= n."""
    if n <= 0:
        raise BitError("n > 0 required")
    return 1 << (n.bit_length() - 1)

def test_prev_basic():
    assert prev_power_of_two(5) == 4


def test_prev_exact():
    assert prev_power_of_two(16) == 16


def test_prev_one():
    assert prev_power_of_two(1) == 1


def test_prev_17():
    assert prev_power_of_two(17) == 16

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
    test_prev_basic()
    test_prev_exact()
    test_prev_one()
    test_prev_17()
    assert stdlib_only()
    print("bit-39 OK: prev-power-of-two")


if __name__ == "__main__":
    main()
