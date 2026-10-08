"""greedy_13: Minimum platforms.

Sweep arrivals and departures in order; a platform frees only when a departure precedes the next arrival.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_13_VERSION = "greedy-13.v1"


def min_platforms(arrivals, departures):
    """Return the minimum platforms so no train waits."""
    arr = sorted(arrivals)
    dep = sorted(departures)
    i = j = 0
    cur = 0
    best = 0
    while i < len(arr) and j < len(dep):
        if arr[i] <= dep[j]:
            cur += 1
            best = max(best, cur)
            i += 1
        else:
            cur -= 1
            j += 1
    return best

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
    assert min_platforms([900, 940, 950, 1100, 1500, 1800], [910, 1200, 1120, 1130, 1900, 2000]) == 3
    assert min_platforms([], []) == 0
    assert min_platforms([900], [1000]) == 1
    assert min_platforms([900, 1000], [930, 1100]) == 1
    assert stdlib_only()
    print("greedy_13 OK")


if __name__ == "__main__":
    main()
