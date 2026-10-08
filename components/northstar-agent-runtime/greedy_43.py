"""greedy_43: Shortest job first average waiting.

Run jobs in increasing burst order to minimize average waiting time.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_43_VERSION = "greedy-43.v1"


def sjf_avg_waiting(bursts):
    """Return the average waiting time under shortest-job-first order."""
    if not bursts:
        return 0.0
    ordered = sorted(bursts)
    wait = 0
    total = 0
    for b in ordered:
        total += wait
        wait += b
    return total / len(ordered)

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
    assert sjf_avg_waiting([6, 8, 7, 3]) == 7.0
    assert sjf_avg_waiting([]) == 0.0
    assert sjf_avg_waiting([5]) == 0.0
    assert sjf_avg_waiting([1, 2, 3]) == 4.0 / 3.0
    assert stdlib_only()
    print("greedy_43 OK")


if __name__ == "__main__":
    main()
