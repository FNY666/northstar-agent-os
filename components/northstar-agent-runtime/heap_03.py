"""Last Stone Weight: simulate smashing stones with a max-heap IS: repeatedly smash the two heaviest stones until at most one remains IS NOT: a physics simulation or a multiset with sorting"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-03.v1"

def _req_stones(value):
    if not isinstance(value, list):
        raise ValueError("stones must be a list")
    for x in value:
        if isinstance(x, bool) or not isinstance(x, int) or x < 0:
            raise ValueError("stones must contain only non-negative ints")
    return list(value)


def last_stone_weight(stones):
    """Return the weight of the last remaining stone (0 if none).

    Fail-closed: ``stones`` must be a list of non-negative ints,
    otherwise :class:`ValueError`.
    """
    stones = _req_stones(stones)
    heap = [-s for s in stones if s > 0]
    heapq.heapify(heap)
    while len(heap) > 1:
        a = -heapq.heappop(heap)
        b = -heapq.heappop(heap)
        if a != b:
            heapq.heappush(heap, -(a - b))
    return -heap[0] if heap else 0

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
    assert last_stone_weight([2, 7, 4, 1, 2, 1]) == 1
    assert last_stone_weight([1]) == 1
    assert last_stone_weight([]) == 0
    assert last_stone_weight([2, 2]) == 0
    assert last_stone_weight([10, 4, 2, 10]) == 2
    try:
        last_stone_weight([1, -2])
    except ValueError:
        pass
    else:
        raise AssertionError("negative stone must raise ValueError")
    assert stdlib_only()
    print("heap-03.v1 OK")


if __name__ == "__main__":
    main()
