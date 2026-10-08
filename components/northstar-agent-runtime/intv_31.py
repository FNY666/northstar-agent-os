"""intv_31: Minimum platforms for trains (min_platforms).

Sort arrivals and departures; a platform frees when departure < arrival.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_31 = "intv-31.v1"


def min_platforms(arrivals, departures):
    """Minimum platforms so no train waits."""
    if not arrivals:
        return 0
    arr = sorted(arrivals)
    dep = sorted(departures)
    i = j = 0
    cur = best = 0
    while i < len(arr):
        if arr[i] <= dep[j]:
            cur += 1
            if cur > best:
                best = cur
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
    assert min_platforms([100, 200], [300, 400]) == 1
    assert min_platforms([], []) == 0
    assert min_platforms([100], [200]) == 1
    assert min_platforms([100, 100, 100], [200, 200, 200]) == 3
    assert stdlib_only()
    print("intv_31 OK")


if __name__ == "__main__":
    main()
