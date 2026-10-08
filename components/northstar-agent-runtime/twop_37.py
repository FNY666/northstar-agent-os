"""rotate_array_left (two-pointer), in-place left rotation by k. IS: exact in-place left rotation using the three-reversal method. IS NOT: a copy-returning rotator; the input list is mutated and nothing is returned."""
from __future__ import annotations

import ast

VERSION = "twop-37.v1"


def _reverse(nums: list[int], lo: int, hi: int) -> None:
    while lo < hi:
        nums[lo], nums[hi] = nums[hi], nums[lo]
        lo += 1
        hi -= 1


def rotate_array_left(nums: list[int], k: int) -> None:
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    if isinstance(k, bool) or not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative integer")
    n = len(nums)
    if n <= 1:
        return
    k %= n
    if k == 0:
        return
    _reverse(nums, 0, k - 1)
    _reverse(nums, k, n - 1)
    _reverse(nums, 0, n - 1)


def stdlib_only() -> bool:
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    a = [1, 2, 3, 4, 5]
    rotate_array_left(a, 2)
    assert a == [3, 4, 5, 1, 2]
    b = [1, 2, 3]
    rotate_array_left(b, 3)
    assert b == [1, 2, 3]
    c = [1, 2, 3, 4]
    rotate_array_left(c, 6)  # k larger than n
    assert c == [3, 4, 1, 2]
    d: list[int] = []
    rotate_array_left(d, 2)  # edge: empty list
    assert d == []
    e = [7]
    rotate_array_left(e, 10)
    assert e == [7]
    try:
        rotate_array_left("123", 1)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("non-list nums must raise ValueError")
    assert stdlib_only()
    print("twop_37 OK")


if __name__ == "__main__":
    main()
