"""trapping_rain_water_two_pass (two-pointer), two-pass DP variant for cross-checking twop_08. IS: a verification variant - one left-to-right pass of running maxima plus one right-to-left pass, trapping water as min(left_max, right_max) - height. IS NOT: a new algorithm (same O(n) time, O(n) space DP idea as twop_08)."""
from __future__ import annotations

import ast

VERSION = "twop-50.v1"


def _is_number(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def trapping_rain_water_two_pass(height: list[int] | list[float]) -> int | float:
    """Return total trapped rain water using two linear passes of running maxima."""
    if not isinstance(height, list):
        raise ValueError("height must be a list")
    for v in height:
        if not _is_number(v):
            raise ValueError("height must contain only numbers")
        if v < 0:
            raise ValueError("height must be non-negative")
    n = len(height)
    if n == 0:
        return 0
    left_max = [0] * n
    cur = height[0]
    for i in range(n):
        if height[i] > cur:
            cur = height[i]
        left_max[i] = cur
    right_max = [0] * n
    cur = height[n - 1]
    for i in range(n - 1, -1, -1):
        if height[i] > cur:
            cur = height[i]
        right_max[i] = cur
    total: int | float = 0
    for i in range(n):
        total += min(left_max[i], right_max[i]) - height[i]
    return total


def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert trapping_rain_water_two_pass([0, 1, 0, 2, 1, 0, 1, 3, 2, 1, 2, 1]) == 6
    assert trapping_rain_water_two_pass([4, 2, 0, 3, 2, 5]) == 9
    assert trapping_rain_water_two_pass([5, 4, 3, 2, 1]) == 0  # edge: descending, no trap
    assert trapping_rain_water_two_pass([]) == 0
    assert trapping_rain_water_two_pass([1, 1, 1]) == 0
    try:
        trapping_rain_water_two_pass([1, -1, 2])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative height")
    assert stdlib_only()
    print("trapping_rain_water_two_pass OK")


if __name__ == "__main__":
    main()
