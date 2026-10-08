"""Maximum Number of Events That Can Be Attended: attend the maximum number of non-overlapping-day events IS: min-heap of event end days swept by day IS NOT: trying every attendance schedule"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-30.v1"

def _req_events(value):
    if not isinstance(value, list):
        raise ValueError("events must be a list")
    out = []
    for i, e in enumerate(value):
        if (not isinstance(e, (list, tuple)) or len(e) != 2
                or any(isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in e)):
            raise ValueError(f"events[{i}] must be a pair of positive ints")
        if e[0] > e[1]:
            raise ValueError(f"events[{i}] start must not exceed end")
        out.append((e[0], e[1]))
    return out


def max_events(events):
    """Return the maximum number of events that can be attended.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    events = _req_events(events)
    events.sort()
    heap = []
    i = 0
    day = 0
    attended = 0
    n = len(events)
    while i < n or heap:
        if not heap:
            day = max(day, events[i][0])
        while i < n and events[i][0] <= day:
            heapq.heappush(heap, events[i][1])
            i += 1
        heapq.heappop(heap)
        attended += 1
        day += 1
        while heap and heap[0] < day:
            heapq.heappop(heap)
    return attended

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
    assert max_events([[1, 2], [2, 3], [3, 4]]) == 3
    assert max_events([[1, 2], [2, 3], [3, 4], [1, 2]]) == 4
    assert max_events([]) == 0
    assert max_events([[1, 1]]) == 1
    try:
        max_events([[3, 1]])
    except ValueError:
        pass
    else:
        raise AssertionError("start > end must raise ValueError")
    assert stdlib_only()
    print("heap-30.v1 OK")


if __name__ == "__main__":
    main()
