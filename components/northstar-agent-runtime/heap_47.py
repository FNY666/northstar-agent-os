"""Maximum Average Pass Ratio: distribute extra students to maximize average pass ratio IS: max-heap by marginal gain of one extra student IS NOT: trying every distribution"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-47.v1"

def _req_inputs(classes, extra):
    if not isinstance(classes, list) or not classes:
        raise ValueError("classes must be a non-empty list")
    for i, c in enumerate(classes):
        if (not isinstance(c, (list, tuple)) or len(c) != 2
                or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in c)):
            raise ValueError(f"classes[{i}] must be a non-negative int pair")
        if c[1] == 0:
            raise ValueError(f"classes[{i}] total must be positive")
    if isinstance(extra, bool) or not isinstance(extra, int) or extra < 0:
        raise ValueError("extraStudents must be a non-negative int")
    return [list(c) for c in classes], extra


def _gain(a, b):
    return (a + 1) / (b + 1) - a / b


def max_average_ratio(classes, extra_students):
    """Return the maximum average pass ratio.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    classes, extra_students = _req_inputs(classes, extra_students)
    heap = [(-_gain(a, b), a, b) for a, b in classes]
    heapq.heapify(heap)
    for _ in range(extra_students):
        _, a, b = heapq.heappop(heap)
        a, b = a + 1, b + 1
        heapq.heappush(heap, (-_gain(a, b), a, b))
    return sum(a / b for _, a, b in heap) / len(heap)

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
    got = max_average_ratio([[1, 2], [3, 5], [2, 2]], 2)
    assert abs(got - 0.7833333333) < 1e-6, got
    got = max_average_ratio([[2, 4], [3, 9], [4, 5], [2, 10]], 4)
    assert abs(got - 0.5348484848) < 1e-6, got
    got = max_average_ratio([[1, 1]], 0)
    assert abs(got - 1.0) < 1e-9, got
    try:
        max_average_ratio([[1, 0]], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("zero total must raise ValueError")
    assert stdlib_only()
    print("heap-47.v1 OK")


if __name__ == "__main__":
    main()
