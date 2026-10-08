"""intv_38: Least intervals with cooling period (task_scheduler).

Count the most frequent task; idle slots are forced by its occurrences.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_38 = "intv-38.v1"


def task_scheduler(tasks, n):
    """Minimum intervals to run all tasks with ``n`` cooldown."""
    if n == 0:
        return len(tasks)
    from collections import Counter
    freq = Counter(tasks)
    max_f = max(freq.values())
    max_n = sum(1 for v in freq.values() if v == max_f)
    return max(len(tasks), (max_f - 1) * (n + 1) + max_n)

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
    assert task_scheduler(["A", "A", "A", "B", "B", "B"], 2) == 8
    assert task_scheduler(["A", "A", "A", "B", "B", "B"], 0) == 6
    assert task_scheduler(["A", "A", "A", "A", "A", "A", "B", "C", "D", "E", "F", "G"], 2) == 16
    assert task_scheduler(["A"], 5) == 1
    assert task_scheduler(["A", "B", "C"], 2) == 3
    assert stdlib_only()
    print("intv_38 OK")


if __name__ == "__main__":
    main()
