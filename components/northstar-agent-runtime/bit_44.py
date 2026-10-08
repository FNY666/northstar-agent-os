"""Total Hamming distance: sum over all pairs via per-bit votes.

Each bit column contributes ones*zeros pairs that differ exactly there.

What this IS: the O(32n) aggregation behind distance sums.
What this IS NOT: a pairwise loop; it never materializes pairs.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_44_VERSION = "bit-total-hamming-distance.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-total-hamming-distance.v1"


class BitError(Exception):
    """Fail-closed."""


def total_hamming_distance(nums: list) -> int:
    """Sum of hamming distances over all pairs (bit-vote per column)."""
    if not nums:
        raise BitError("empty input")
    for v in nums:
        if v < 0:
            raise BitError("non-negative only")
    total = 0
    m = len(nums)
    for i in range(32):
        ones = 0
        for v in nums:
            ones += (v >> i) & 1
        total += ones * (m - ones)
    return total

def test_thd_basic():
    assert total_hamming_distance([4, 14, 2]) == 6


def test_thd_dup():
    assert total_hamming_distance([4, 14, 4]) == 4


def test_thd_single():
    assert total_hamming_distance([0]) == 0


def test_thd_empty_raises():
    try:
        total_hamming_distance([])
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
    test_thd_basic()
    test_thd_dup()
    test_thd_single()
    test_thd_empty_raises()
    assert stdlib_only()
    print("bit-44 OK: total-hamming-distance")


if __name__ == "__main__":
    main()
