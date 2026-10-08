"""slide_39: Minimum swaps to group all 1s together.

Fixed-size window of length = number of ones: the best window holds the most ones, minimizing swaps.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_39_VERSION = "slide-39.v1"


def min_swaps_ones(data):
    """Min swaps to group all 1s together."""
    ones = sum(data)
    if ones <= 1:
        return 0
    window = sum(data[:ones])
    best = window
    for i in range(ones, len(data)):
        window += data[i] - data[i - ones]
        if window > best:
            best = window
    return ones - best

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
    assert min_swaps_ones([1, 0, 1, 0, 1]) == 1
    assert min_swaps_ones([0, 0, 0, 1, 0]) == 0
    assert min_swaps_ones([1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1]) == 3
    assert min_swaps_ones([1, 1, 1]) == 0
    assert min_swaps_ones([0, 0, 0]) == 0
    assert stdlib_only()
    print("slide_39 OK")


if __name__ == "__main__":
    main()
