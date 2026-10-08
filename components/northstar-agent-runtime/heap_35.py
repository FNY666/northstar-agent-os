"""Single-Threaded CPU: order in which a single-threaded CPU processes tasks IS: min-heap of available tasks keyed by (duration, index) IS NOT: simulating every scheduling decision"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-35.v1"

def _req_tasks(value):
    if not isinstance(value, list):
        raise ValueError("tasks must be a list")
    out = []
    for i, t in enumerate(value):
        if (not isinstance(t, (list, tuple)) or len(t) != 2
                or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in t)):
            raise ValueError(f"tasks[{i}] must be a non-negative int pair")
        out.append((t[0], t[1]))
    return out


def get_order(tasks):
    """Return the processing order of task indices.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    tasks = _req_tasks(tasks)
    indexed = sorted(enumerate(tasks), key=lambda x: x[1][0])
    heap = []
    i = 0
    t = 0
    order = []
    n = len(indexed)
    while len(order) < n:
        while i < n and indexed[i][1][0] <= t:
            idx, (enq, dur) = indexed[i]
            heapq.heappush(heap, (dur, idx))
            i += 1
        if heap:
            dur, idx = heapq.heappop(heap)
            order.append(idx)
            t += dur
        else:
            t = indexed[i][1][0]
    return order

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
    assert get_order([[1, 2], [2, 4], [3, 2], [4, 1]]) == [0, 2, 3, 1]
    assert get_order([[7, 10], [7, 12], [7, 5], [7, 4], [7, 2]]) == [4, 3, 2, 0, 1]
    assert get_order([]) == []
    assert get_order([[0, 1]]) == [0]
    try:
        get_order([[1, -2]])
    except ValueError:
        pass
    else:
        raise AssertionError("negative duration must raise ValueError")
    assert stdlib_only()
    print("heap-35.v1 OK")


if __name__ == "__main__":
    main()
