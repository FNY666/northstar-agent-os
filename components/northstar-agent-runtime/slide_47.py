"""slide_47: Minimum recolors to get k consecutive black blocks.

Fixed-size window: count white blocks inside each window of length k and take the minimum.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_47_VERSION = "slide-47.v1"


def min_recolors(blocks, k):
    """Min recolors to get k consecutive black blocks."""
    n = len(blocks)
    if k > n:
        return 0
    window = sum(1 for ch in blocks[:k] if ch == "W")
    best = window
    for i in range(k, n):
        if blocks[i] == "W":
            window += 1
        if blocks[i - k] == "W":
            window -= 1
        if window < best:
            best = window
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
    assert min_recolors("WBBWWBBWBW", 7) == 3
    assert min_recolors("WBWBBBW", 2) == 0
    assert min_recolors("BBBBB", 3) == 0
    assert min_recolors("WWWWW", 2) == 2
    assert min_recolors("W", 1) == 1
    assert stdlib_only()
    print("slide_47 OK")


if __name__ == "__main__":
    main()
