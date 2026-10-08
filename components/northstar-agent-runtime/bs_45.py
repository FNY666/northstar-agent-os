"""bs_45: Maximum running time of computers

Maximum minutes n computers can run simultaneously from the
battery pool (binary search on answer).

Time complexity: O(n log(sum/n)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_45_VERSION = "bs-45.v1"


def max_run_time(n, batteries):
    """Return the maximum simultaneous run time for n computers."""
    lo, hi = 0, sum(batteries) // n

    def feasible(t):
        return sum(min(b, t) for b in batteries) >= t * n

    while lo < hi:
        mid = (lo + hi + 1) // 2
        if feasible(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo

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
    assert max_run_time(2, [3, 3, 3]) == 4
    assert max_run_time(2, [1, 1, 1, 1]) == 2
    assert max_run_time(3, [10, 10, 3, 5]) == 8
    assert max_run_time(1, [5]) == 5
    assert stdlib_only()
    print("bs_45 OK")


if __name__ == "__main__":
    main()
