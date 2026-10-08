"""intv_40: Jump game reachability over intervals (can_jump).

Greedy: track the farthest reachable index.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_40 = "intv-40.v1"


def can_jump(nums):
    """True when the last index is reachable."""
    reach = 0
    for i, jump in enumerate(nums):
        if i > reach:
            return False
        if i + jump > reach:
            reach = i + jump
    return True

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
    assert can_jump([2, 3, 1, 1, 4]) is True
    assert can_jump([3, 2, 1, 0, 4]) is False
    assert can_jump([0]) is True
    assert can_jump([1, 0, 1, 0]) is False
    assert can_jump([2, 0, 0]) is True
    assert stdlib_only()
    print("intv_40 OK")


if __name__ == "__main__":
    main()
