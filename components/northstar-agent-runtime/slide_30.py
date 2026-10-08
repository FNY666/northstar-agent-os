"""slide_30: Diet plan performance.

Fixed-size window: score each k-day window +1 when above the upper bound and -1 when below the lower bound.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_30_VERSION = "slide-30.v1"


def diet_plan(calories, k, lower, upper):
    """Diet plan performance: +1 / -1 per k-day window vs bounds."""
    n = len(calories)
    if n == 0 or k <= 0 or k > n:
        return 0
    window = sum(calories[:k])
    points = 0
    if window < lower:
        points -= 1
    elif window > upper:
        points += 1
    for i in range(k, n):
        window += calories[i] - calories[i - k]
        if window < lower:
            points -= 1
        elif window > upper:
            points += 1
    return points

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
    assert diet_plan([1, 2, 3, 4, 5], 1, 3, 3) == 0
    assert diet_plan([3, 2], 2, 0, 1) == 1
    assert diet_plan([6, 5, 0, 0], 2, 1, 5) == 0
    assert diet_plan([6, 13, 8, 7, 10, 1, 12, 11], 6, 5, 37) == 3
    assert diet_plan([], 1, 0, 1) == 0
    assert stdlib_only()
    print("slide_30 OK")


if __name__ == "__main__":
    main()
