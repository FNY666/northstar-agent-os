"""Next power of two: smallest 2^k >= n via bit smearing.

Filling below the MSB then adding one carries into the next power of two.

What this IS: the allocator rounding primitive.
What this IS NOT: a ceiling for floats; integers only.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_38_VERSION = "bit-next-power-of-two.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-next-power-of-two.v1"


class BitError(Exception):
    """Fail-closed."""


def next_power_of_two(n: int) -> int:
    """Smallest power of two >= n."""
    if n <= 0:
        raise BitError("n > 0 required")
    n -= 1
    n |= n >> 1
    n |= n >> 2
    n |= n >> 4
    n |= n >> 8
    n |= n >> 16
    n |= n >> 32
    return n + 1

def test_next_basic():
    assert next_power_of_two(5) == 8


def test_next_exact():
    assert next_power_of_two(16) == 16


def test_next_one():
    assert next_power_of_two(1) == 1


def test_next_17():
    assert next_power_of_two(17) == 32


def test_next_zero_raises():
    try:
        next_power_of_two(0)
    except BitError:
        return
    raise AssertionError("expected BitError")

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
    test_next_basic()
    test_next_exact()
    test_next_one()
    test_next_17()
    test_next_zero_raises()
    assert stdlib_only()
    print("bit-38 OK: next-power-of-two")


if __name__ == "__main__":
    main()
