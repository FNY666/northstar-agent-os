"""greedy_20: Task scheduler.

The answer is driven by the most frequent task: idle slots follow (max_count-1)*(n+1)+num_max.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_20_VERSION = "greedy-20.v1"


def least_interval(tasks, n):
    """Return the minimum intervals to run all tasks with cooldown n."""
    from collections import Counter
    if not tasks:
        return 0
    counts = Counter(tasks)
    max_c = max(counts.values())
    num_max = sum(1 for c in counts.values() if c == max_c)
    return max(len(tasks), (max_c - 1) * (n + 1) + num_max)

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
    assert least_interval(["A", "A", "A", "B", "B", "B"], 2) == 8
    assert least_interval(["A", "A", "A", "B", "B", "B"], 0) == 6
    assert least_interval([], 2) == 0
    assert least_interval(["A", "A", "A", "A", "A", "A", "B", "C", "D", "E", "F", "G"], 2) == 16
    assert stdlib_only()
    print("greedy_20 OK")


if __name__ == "__main__":
    main()
