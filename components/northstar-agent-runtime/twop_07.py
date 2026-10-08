"""Container With Most Water (two-pointer), find the pair of lines holding the most water. IS: a converging two-pointer scan that always moves the shorter line. IS NOT: a brute-force O(n^2) pair check."""

from __future__ import annotations

import ast

VERSION = "twop-07.v1"


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


def container_most_water(height: list[int]) -> int:
    """Return the maximum ``min(h[i], h[j]) * (j - i)`` area.

    Fail-closed: ``height`` must be a list of at least 2 non-negative ints,
    otherwise :class:`ValueError`.
    """
    h = _check_heights(height, "height")
    if len(h) < 2:
        raise ValueError("height must contain at least 2 lines")
    best = 0
    lo, hi = 0, len(h) - 1
    while lo < hi:
        area = min(h[lo], h[hi]) * (hi - lo)
        if area > best:
            best = area
        if h[lo] < h[hi]:
            lo += 1
        else:
            hi -= 1
    return best


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
    assert container_most_water([1, 8, 6, 2, 5, 4, 8, 3, 7]) == 49
    assert container_most_water([1, 1]) == 1
    assert container_most_water([0, 0, 0]) == 0  # edge: all zero
    try:
        container_most_water([1, -2, 3])
    except ValueError:
        pass
    else:
        raise AssertionError("negative height must raise ValueError")
    try:
        container_most_water([5])
    except ValueError:
        pass
    else:
        raise AssertionError("fewer than 2 lines must raise ValueError")
    assert stdlib_only()
    print("twop_07 OK")


if __name__ == "__main__":
    main()
