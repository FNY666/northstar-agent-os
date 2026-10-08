"""Missing number: find the missing 0..n value via XOR.

XORs the index range against the array; every present value cancels, leaving the missing one.

What this IS: an O(n) time, O(1) space missing-number finder.
What this IS NOT: a sorter; input order is irrelevant.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_04_VERSION = "bit-missing-number.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-missing-number.v1"


class BitError(Exception):
    """Fail-closed."""


def missing_number(nums: list) -> int:
    """Numbers are 0..n with one missing; find it via XOR."""
    x = len(nums)
    for i, v in enumerate(nums):
        x ^= i ^ v
    return x

def test_missing_basic():
    assert missing_number([3, 0, 1]) == 2


def test_missing_two():
    assert missing_number([0, 1]) == 2


def test_missing_large():
    assert missing_number([9, 6, 4, 2, 3, 5, 7, 0, 1]) == 8

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
    test_missing_basic()
    test_missing_two()
    test_missing_large()
    assert stdlib_only()
    print("bit-04 OK: missing-number")


if __name__ == "__main__":
    main()
