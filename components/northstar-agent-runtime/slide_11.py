"""slide_11: Fruit into baskets.

Variable window with at most two distinct values: shrink the left edge whenever a third fruit type enters the window.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_11_VERSION = "slide-11.v1"


def fruit_baskets(fruits):
    """Longest subarray with at most 2 distinct values."""
    counts = {}
    left = 0
    best = 0
    for right, f in enumerate(fruits):
        counts[f] = counts.get(f, 0) + 1
        while len(counts) > 2:
            counts[fruits[left]] -= 1
            if counts[fruits[left]] == 0:
                del counts[fruits[left]]
            left += 1
        if right - left + 1 > best:
            best = right - left + 1
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
    assert fruit_baskets([1, 2, 1]) == 3
    assert fruit_baskets([0, 1, 2, 2]) == 3
    assert fruit_baskets([1, 2, 3, 2, 2]) == 4
    assert fruit_baskets([]) == 0
    assert fruit_baskets([1]) == 1
    assert stdlib_only()
    print("slide_11 OK")


if __name__ == "__main__":
    main()
