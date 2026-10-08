"""Process Tasks Using Servers: assign each task to a server, waiting if all busy IS: min-heap of free servers plus min-heap of busy (free_time, server) IS NOT: simulating every second"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-44.v1"

def _req_inputs(n, tasks):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    if not isinstance(tasks, list):
        raise ValueError("tasks must be a list")
    out = []
    for i, t in enumerate(tasks):
        if (not isinstance(t, (list, tuple)) or len(t) != 2
                or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in t)):
            raise ValueError(f"tasks[{i}] must be a non-negative int pair")
        out.append((t[0], t[1]))
    return n, out


def busiest_servers(n, tasks):
    """Return the server index assigned to each task.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    n, tasks = _req_inputs(n, tasks)
    indexed = sorted(enumerate(tasks), key=lambda x: (x[1][0], x[0]))
    free = list(range(n))
    heapq.heapify(free)
    busy = []
    ans = [0] * len(tasks)
    t = 0
    for idx, (enq, dur) in indexed:
        t = max(t, enq)
        while busy and busy[0][0] <= t:
            _, s = heapq.heappop(busy)
            heapq.heappush(free, s)
        if not free:
            ft, s = heapq.heappop(busy)
            t = ft
            heapq.heappush(free, s)
            while busy and busy[0][0] <= t:
                _, s2 = heapq.heappop(busy)
                heapq.heappush(free, s2)
        s = heapq.heappop(free)
        heapq.heappush(busy, (t + dur, s))
        ans[idx] = s
    return ans

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
    assert busiest_servers(2, [[0, 3], [1, 9], [2, 6]]) == [0, 1, 0]
    assert busiest_servers(1, [[0, 1], [0, 2]]) == [0, 0]
    assert busiest_servers(3, []) == []
    got = busiest_servers(2, [[1, 5], [2, 7], [3, 4]])
    assert got == [0, 1, 0], got
    try:
        busiest_servers(0, [])
    except ValueError:
        pass
    else:
        raise AssertionError("n=0 must raise ValueError")
    assert stdlib_only()
    print("heap-44.v1 OK")


if __name__ == "__main__":
    main()
