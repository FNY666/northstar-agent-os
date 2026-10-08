"""Trapping Rain Water (two-pointer), compute total trapped water in O(1) extra space. IS: a converging two-pointer scan tracking running left/right maxima. IS NOT: a prefix/suffix-max array solution."""

from __future__ import annotations

import ast

VERSION = "twop-08.v1"


def _check_heights(values: object, name: str) -> list[int]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(
                f"{name} elements must be int, got {type(v).__name__}"
            )
        if v < 0:
            raise ValueError(f"{name} elements must be non-negative")
    return list(values)


def trapping_rain_water(height: list[int]) -> int:
    """Return the total units of water trapped after raining.

    Fail-closed: ``height`` must be a list of non-negative ints, otherwise
    :class:`ValueError`. Fewer than 3 bars trap nothing (edge: returns 0).
    """
    h = _check_heights(height, "height")
    n = len(h)
    if n < 3:
        return 0
    lo, hi = 0, n - 1
    left_max, right_max = 0, 0
    water = 0
    while lo < hi:
        if h[lo] < h[hi]:
            if h[lo] >= left_max:
                left_max = h[lo]
            else:
                water += left_max - h[lo]
            lo += 1
        else:
            if h[hi] >= right_max:
                right_max = h[hi]
            else:
                water += right_max - h[hi]
            hi -= 1
    return water


def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
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
    assert trapping_rain_water([0, 1, 0, 2, 1, 0, 1, 3, 2, 1, 2, 1]) == 6
    assert trapping_rain_water([4, 2, 0, 3, 2, 5]) == 9
    assert trapping_rain_water([]) == 0  # edge: empty list
    assert trapping_rain_water([1, 2, 3]) == 0  # edge: strictly rising
    assert trapping_rain_water([5, 5, 5, 5]) == 0
    try:
        trapping_rain_water([2, -1, 2])
    except ValueError:
        pass
    else:
        raise AssertionError("negative height must raise ValueError")
    assert stdlib_only()
    print("twop_08 OK")


if __name__ == "__main__":
    main()
