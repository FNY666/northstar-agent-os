"""K Closest Points to Origin: return the k points closest to the origin IS: heapq.nsmallest with squared distance as key IS NOT: computing square roots or sorting all points"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-06.v1"

def _req_points(value):
    if not isinstance(value, list) or not value:
        raise ValueError("points must be a non-empty list")
    out = []
    for i, p in enumerate(value):
        if (not isinstance(p, (list, tuple)) or len(p) != 2
                or any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in p)):
            raise ValueError(f"points[{i}] must be a pair of numbers")
        out.append((p[0], p[1]))
    return out


def _req_k(k, n):
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an int")
    if not 1 <= k <= n:
        raise ValueError("k must satisfy 1 <= k <= len(points)")
    return k


def k_closest_points(points, k):
    """Return the k points closest to the origin.

    Fail-closed: points must be a non-empty list of numeric pairs and
    ``1 <= k <= len(points)``, else :class:`ValueError`.
    """
    points = _req_points(points)
    k = _req_k(k, len(points))
    return [list(p) for p in heapq.nsmallest(k, points, key=lambda p: p[0] ** 2 + p[1] ** 2)]

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
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
    got = k_closest_points([[1, 3], [-2, 2]], 1)
    assert got == [[-2, 2]], got
    got = k_closest_points([[3, 3], [5, -1], [-2, 4]], 2)
    assert sorted(got) == [[-2, 4], [3, 3]], got
    try:
        k_closest_points([[1, 2, 3]], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("non-pair must raise ValueError")
    try:
        k_closest_points([[0, 0]], 2)
    except ValueError:
        pass
    else:
        raise AssertionError("k > len must raise ValueError")
    assert stdlib_only()
    print("heap-06.v1 OK")


if __name__ == "__main__":
    main()
