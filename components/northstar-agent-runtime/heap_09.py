"""Task Scheduler: minimum intervals to run tasks with cooldown n IS: greedy simulation with a max-heap of remaining counts IS NOT: brute-force search over schedules"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-09.v1"

def _req_tasks(value):
    if not isinstance(value, list) or not value:
        raise ValueError("tasks must be a non-empty list")
    for i, t in enumerate(value):
        if not isinstance(t, str) or len(t) != 1:
            raise ValueError(f"tasks[{i}] must be a single character")
    return list(value)


def _req_n(n):
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("n must be a non-negative int")
    return n


def least_interval(tasks, n):
    """Return the fewest intervals needed with cooldown ``n``.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    tasks = _req_tasks(tasks)
    n = _req_n(n)
    freq = {}
    for t in tasks:
        freq[t] = freq.get(t, 0) + 1
    heap = [-c for c in freq.values()]
    heapq.heapify(heap)
    time = 0
    while heap:
        cycle = []
        for _ in range(n + 1):
            if heap:
                cycle.append(-heapq.heappop(heap))
        for c in cycle:
            if c - 1 > 0:
                heapq.heappush(heap, -(c - 1))
        time += n + 1 if heap else len(cycle)
    return time

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
    assert least_interval(["A", "A", "A", "B", "B", "B"], 2) == 8
    assert least_interval(["A", "A", "A", "B", "B", "B"], 0) == 6
    assert least_interval(["A"], 2) == 1
    assert least_interval(["A", "A", "A", "A"], 3) == 13
    try:
        least_interval([], 2)
    except ValueError:
        pass
    else:
        raise AssertionError("empty tasks must raise ValueError")
    try:
        least_interval(["A"], -1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative n must raise ValueError")
    assert stdlib_only()
    print("heap-09.v1 OK")


if __name__ == "__main__":
    main()
