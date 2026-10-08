"""Course Schedule III: maximum number of courses that can be taken IS: max-heap of taken durations, dropping the longest when over time IS NOT: trying every course subset"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-31.v1"

def _req_courses(value):
    if not isinstance(value, list):
        raise ValueError("courses must be a list")
    out = []
    for i, c in enumerate(value):
        if (not isinstance(c, (list, tuple)) or len(c) != 2
                or any(isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in c)):
            raise ValueError(f"courses[{i}] must be a pair of positive ints")
        out.append((c[0], c[1]))
    return out


def schedule_course(courses):
    """Return the maximum number of courses that can be taken.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    courses = _req_courses(courses)
    courses.sort(key=lambda c: c[1])
    heap = []
    spent = 0
    for dur, last in courses:
        heapq.heappush(heap, -dur)
        spent += dur
        if spent > last:
            spent += heapq.heappop(heap)
    return len(heap)

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
    assert schedule_course([[100, 200], [200, 1300], [1000, 1250], [2000, 3200]]) == 3
    assert schedule_course([[1, 2]]) == 1
    assert schedule_course([[3, 2], [4, 3]]) == 0
    assert schedule_course([]) == 0
    try:
        schedule_course([[0, 5]])
    except ValueError:
        pass
    else:
        raise AssertionError("zero duration must raise ValueError")
    assert stdlib_only()
    print("heap-31.v1 OK")


if __name__ == "__main__":
    main()
