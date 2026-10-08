"""circular_tour: gas-station circular tour: first start index that completes the circuit, -1 if none. IS: a start index or -1; mismatched/negative inputs raise ValueError. IS NOT: an O(n^2) brute-force circuit check."""

from __future__ import annotations

import ast
from typing import List
VERSION = "queue-23.v1"

def _req_stations(vals: object, name: str) -> List[int]:
    if not isinstance(vals, list) or not vals:
        raise ValueError(f"{name} must be a non-empty list")
    for v in vals:
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError(f"{name} must contain non-negative ints")
    return list(vals)


def circular_tour(petrol: List[int], dist: List[int]) -> int:
    """Return the first station index from which the full circuit is possible."""
    petrol = _req_stations(petrol, "petrol")
    dist = _req_stations(dist, "dist")
    if len(petrol) != len(dist):
        raise ValueError("petrol and dist must have equal length")
    total = tank = start = 0
    for i, (p, d) in enumerate(zip(petrol, dist)):
        diff = p - d
        total += diff
        tank += diff
        if tank < 0:
            start = i + 1
            tank = 0
    return start if total >= 0 else -1


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
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
    assert circular_tour([1, 2, 3, 4, 5], [3, 4, 5, 1, 2]) == 3
    assert circular_tour([2, 3, 4], [3, 4, 3]) == -1
    assert circular_tour([5], [4]) == 0
    assert circular_tour([3], [4]) == -1
    try:
        circular_tour([1, 2], [1])
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched lengths must raise ValueError")
    try:
        circular_tour([1, -2], [1, 1])
    except ValueError:
        pass
    else:
        raise AssertionError("negative petrol must raise ValueError")
    assert stdlib_only()
    print("queue-23 OK: gas-station circuit")


if __name__ == "__main__":
    main()
