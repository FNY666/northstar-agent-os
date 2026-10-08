"""Majority element via bits: >n/2 element by per-bit vote.

The majority element wins every bit column it sets, so voting each column reconstructs it.

What this IS: the bit-voting majority finder, O(32n) time.
What this IS NOT: a Boyer-Moore pass; it needs the majority to exist.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_49_VERSION = "bit-majority-element-bits.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-majority-element-bits.v1"


class BitError(Exception):
    """Fail-closed."""


def majority_element_bits(nums: list) -> int:
    """Majority element (> n/2 occurrences) via per-bit vote."""
    if not nums:
        raise BitError("empty input")
    for v in nums:
        if v < 0:
            raise BitError("non-negative only")
    res = 0
    for i in range(32):
        ones = 0
        for v in nums:
            ones += (v >> i) & 1
        if ones > len(nums) // 2:
            res |= 1 << i
    return res

def test_maj_basic():
    assert majority_element_bits([3, 2, 3]) == 3


def test_maj_long():
    assert majority_element_bits([2, 2, 1, 1, 1, 2, 2]) == 2


def test_maj_single():
    assert majority_element_bits([1]) == 1


def test_maj_empty_raises():
    try:
        majority_element_bits([])
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
    test_maj_basic()
    test_maj_long()
    test_maj_single()
    test_maj_empty_raises()
    assert stdlib_only()
    print("bit-49 OK: majority-element-bits")


if __name__ == "__main__":
    main()
