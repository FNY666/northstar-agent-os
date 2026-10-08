"""Boats to Save People (two-pointer), find the minimum boats with at most two people each. IS: a greedy lightest-plus-heaviest pairing on sorted weights. IS NOT: a bin-packing solver."""

from __future__ import annotations

import ast

VERSION = "twop-10.v1"


def _check_weights(values: object, name: str) -> list[int]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(
                f"{name} elements must be int, got {type(v).__name__}"
            )
        if v <= 0:
            raise ValueError(f"{name} elements must be positive")
    return list(values)


def _check_limit(limit: object) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an int")
    if limit <= 0:
        raise ValueError("limit must be positive")
    return limit


def boats_to_save_people(people: list[int], limit: int) -> int:
    """Return the minimum boats needed (each boat: at most 2, weight <= limit).

    Fail-closed: ``people`` must be a list of positive ints and ``limit`` a
    positive int; anyone heavier than ``limit`` can never board, so both
    raise :class:`ValueError`.
    """
    weights = sorted(_check_weights(people, "people"))
    limit = _check_limit(limit)
    for w in weights:
        if w > limit:
            raise ValueError(
                f"person weight {w} exceeds boat limit {limit}"
            )
    lo, hi = 0, len(weights) - 1
    boats = 0
    while lo <= hi:
        if weights[lo] + weights[hi] <= limit:
            lo += 1
        hi -= 1
        boats += 1
    return boats


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
    assert boats_to_save_people([1, 2], 3) == 1
    assert boats_to_save_people([3, 2, 2, 1], 3) == 3
    assert boats_to_save_people([3, 5, 3, 4], 5) == 4
    assert boats_to_save_people([], 5) == 0  # edge: nobody to rescue
    try:
        boats_to_save_people([4, 2], 3)
    except ValueError:
        pass
    else:
        raise AssertionError("weight over limit must raise ValueError")
    try:
        boats_to_save_people([1, 2], 0)
    except ValueError:
        pass
    else:
        raise AssertionError("non-positive limit must raise ValueError")
    assert stdlib_only()
    print("twop_10 OK")


if __name__ == "__main__":
    main()
