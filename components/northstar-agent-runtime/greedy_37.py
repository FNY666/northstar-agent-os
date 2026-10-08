"""greedy_37: Minimize maximum lateness (EDD).

Earliest-deadline-first order provably minimizes the maximum lateness.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_37_VERSION = "greedy-37.v1"


def min_max_lateness(jobs):
    """Return the minimum achievable maximum lateness.

    jobs: iterable of (duration, deadline) pairs.
    """
    ordered = sorted(jobs, key=lambda j: j[1])
    t = 0
    worst = float("-inf")
    for duration, deadline in ordered:
        t += duration
        worst = max(worst, t - deadline)
    return worst if ordered else 0

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
    assert min_max_lateness([(3, 6), (2, 8), (1, 9), (4, 9), (3, 14), (2, 15)]) == 1
    assert min_max_lateness([]) == 0
    assert min_max_lateness([(1, 1)]) == 0
    assert min_max_lateness([(5, 3)]) == 2
    assert stdlib_only()
    print("greedy_37 OK")


if __name__ == "__main__":
    main()
