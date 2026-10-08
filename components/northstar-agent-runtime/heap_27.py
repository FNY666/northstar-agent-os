"""Furthest Building You Can Reach: how far you can climb with bricks and ladders IS: min-heap keeping the largest climbs on ladders IS NOT: trying every bricks/ladders assignment"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-27.v1"

def _req_inputs(heights, bricks, ladders):
    if not isinstance(heights, list) or not heights:
        raise ValueError("heights must be a non-empty list")
    for i, h in enumerate(heights):
        if isinstance(h, bool) or not isinstance(h, (int, float)) or h < 0:
            raise ValueError(f"heights[{i}] must be a non-negative number")
    if isinstance(bricks, bool) or not isinstance(bricks, int) or bricks < 0:
        raise ValueError("bricks must be a non-negative int")
    if isinstance(ladders, bool) or not isinstance(ladders, int) or ladders < 0:
        raise ValueError("ladders must be a non-negative int")
    return list(heights), bricks, ladders


def furthest_building(heights, bricks, ladders):
    """Return the furthest reachable building index.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    heights, bricks, ladders = _req_inputs(heights, bricks, ladders)
    climbs = []
    for i in range(len(heights) - 1):
        diff = heights[i + 1] - heights[i]
        if diff <= 0:
            continue
        heapq.heappush(climbs, diff)
        if len(climbs) > ladders:
            bricks -= heapq.heappop(climbs)
        if bricks < 0:
            return i
    return len(heights) - 1

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
    assert furthest_building([4, 2, 7, 6, 9, 14, 12], 5, 1) == 4
    assert furthest_building([4, 12, 2, 7, 3, 18, 20, 3, 19], 10, 2) == 7
    assert furthest_building([14, 3, 19, 3], 17, 0) == 3
    assert furthest_building([1], 0, 0) == 0
    try:
        furthest_building([1, 2], -1, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("negative bricks must raise ValueError")
    assert stdlib_only()
    print("heap-27.v1 OK")


if __name__ == "__main__":
    main()
