"""Single number III: two lone elements among doubles.

XOR of everything gives a^b; its lowest set bit partitions the array into two single-number problems.

What this IS: the linear-time partition trick for exactly two singles.
What this IS NOT: a general k-singles solver; it assumes exactly two.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_25_VERSION = "bit-single-number-iii.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-single-number-iii.v1"


class BitError(Exception):
    """Fail-closed."""


def single_number_iii(nums: list) -> tuple:
    """Two singles among doubles; partition by a differing bit."""
    if len(nums) < 2:
        raise BitError("need >= 2 elements")
    xor_all = 0
    for x in nums:
        xor_all ^= x
    diff = xor_all & -xor_all
    a = 0
    for x in nums:
        if x & diff:
            a ^= x
    return (a, xor_all ^ a)

def test_iii_basic():
    assert sorted(single_number_iii([1, 2, 1, 3, 2, 5])) == [3, 5]


def test_iii_pair():
    assert sorted(single_number_iii([0, 1])) == [0, 1]


def test_iii_short_raises():
    try:
        single_number_iii([7])
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
    test_iii_basic()
    test_iii_pair()
    test_iii_short_raises()
    assert stdlib_only()
    print("bit-25 OK: single-number-iii")


if __name__ == "__main__":
    main()
