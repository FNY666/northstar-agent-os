"""Population count: count set bits with Kernighan's trick.

Repeatedly clears the lowest set bit (n &= n - 1); each iteration removes exactly one 1-bit, so the loop runs in O(popcount).

What this IS: a real O(k) popcount for k set bits, fail-closed on negatives.
What this IS NOT: a substitute for int.bit_count(); the host picks the counter.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_01_VERSION = "bit-popcount.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-popcount.v1"


class BitError(Exception):
    """Fail-closed."""


MASK_NONE = 0  # placeholder to keep module shape uniform


def popcount(n: int) -> int:
    """Count set bits (Kernighan). Fail-closed on negatives."""
    if n < 0:
        raise BitError("popcount needs n >= 0")
    count = 0
    while n:
        n &= n - 1
        count += 1
    return count

def test_popcount_zero():
    assert popcount(0) == 0


def test_popcount_basic():
    assert popcount(0b101101) == 4


def test_popcount_all_ones():
    assert popcount(0xFF) == 8


def test_popcount_negative_raises():
    try:
        popcount(-1)
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
    test_popcount_zero()
    test_popcount_basic()
    test_popcount_all_ones()
    test_popcount_negative_raises()
    assert stdlib_only()
    print("bit-01 OK: popcount")


if __name__ == "__main__":
    main()
