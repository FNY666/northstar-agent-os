"""greedy_47: Broken calculator.

Work backwards from the target: halve evens, increment odds; then add the remaining gap.

Time complexity: O(log target) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_47_VERSION = "greedy-47.v1"


def broken_calc(start_value, target):
    """Return the minimum operations (double or decrement) to reach target."""
    ops = 0
    while target > start_value:
        ops += 1
        if target % 2:
            target += 1
        else:
            target //= 2
    return ops + (start_value - target)

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
    assert broken_calc(2, 3) == 2
    assert broken_calc(5, 8) == 2
    assert broken_calc(3, 10) == 3
    assert broken_calc(1024, 1) == 1023
    assert stdlib_only()
    print("greedy_47 OK")


if __name__ == "__main__":
    main()
