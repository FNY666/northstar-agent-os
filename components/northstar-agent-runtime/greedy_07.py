"""greedy_07: Jump game reachability.

Track the farthest reachable index; if the scan index ever exceeds it, the end is unreachable.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_07_VERSION = "greedy-07.v1"


def can_jump(nums):
    """Return True if the last index is reachable from the first."""
    reach = 0
    for i, v in enumerate(nums):
        if i > reach:
            return False
        reach = max(reach, i + v)
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
    assert can_jump([1, 0]) is True
    assert stdlib_only()
    print("greedy_07 OK")


if __name__ == "__main__":
    main()
