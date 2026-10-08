"""greedy_32: Course schedule III.

Take courses by deadline; drop the longest one seen so far when over budget.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_32_VERSION = "greedy-32.v1"


def schedule_courses(courses):
    """Return the maximum number of courses that can be taken."""
    import heapq
    ordered = sorted(courses, key=lambda c: c[1])
    heap = []
    time = 0
    for duration, last_day in ordered:
        heapq.heappush(heap, -duration)
        time += duration
        if time > last_day:
            time += heapq.heappop(heap)
    return len(heap)

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True



def main() -> None:
    assert schedule_courses([[100, 200], [200, 1300], [1000, 1250], [2000, 3200]]) == 3
    assert schedule_courses([[1, 2]]) == 1
    assert schedule_courses([]) == 0
    assert schedule_courses([[3, 2], [4, 3]]) == 0
    assert stdlib_only()
    print("greedy_32 OK")


if __name__ == "__main__":
    main()
