"""Meeting Rooms II: minimum number of rooms for overlapping meetings IS: min-heap of meeting end times IS NOT: a sweep line without a heap"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-16.v1"

def _req_intervals(value):
    if not isinstance(value, list):
        raise ValueError("intervals must be a list")
    out = []
    for i, iv in enumerate(value):
        if (not isinstance(iv, (list, tuple)) or len(iv) != 2
                or any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in iv)):
            raise ValueError(f"intervals[{i}] must be a numeric pair")
        if iv[0] > iv[1]:
            raise ValueError(f"intervals[{i}] start must not exceed end")
        out.append((iv[0], iv[1]))
    return out


def min_meeting_rooms(intervals):
    """Return the minimum number of meeting rooms required.

    Fail-closed: intervals must be a list of valid numeric pairs,
    else :class:`ValueError`.
    """
    intervals = _req_intervals(intervals)
    intervals.sort()
    ends = []
    for s, e in intervals:
        if ends and ends[0] <= s:
            heapq.heappop(ends)
        heapq.heappush(ends, e)
    return len(ends)

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
    assert min_meeting_rooms([[0, 30], [5, 10], [15, 20]]) == 2
    assert min_meeting_rooms([[7, 10], [2, 4]]) == 1
    assert min_meeting_rooms([]) == 0
    assert min_meeting_rooms([[1, 5], [5, 10]]) == 1
    try:
        min_meeting_rooms([[5, 1]])
    except ValueError:
        pass
    else:
        raise AssertionError("start > end must raise ValueError")
    assert stdlib_only()
    print("heap-16.v1 OK")


if __name__ == "__main__":
    main()
