"""slide_21: Grumpy bookstore owner.

Fixed-size window: add the customers of grumpy minutes inside the secret-technique window to the always-satisfied base.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_21_VERSION = "slide-21.v1"


def max_satisfied(customers, grumpy, minutes):
    """Max satisfied customers using the technique for `minutes`."""
    n = len(customers)
    base = 0
    for i in range(n):
        if grumpy[i] == 0:
            base += customers[i]
    extra = 0
    window = 0
    for i in range(n):
        if grumpy[i] == 1:
            window += customers[i]
        if i >= minutes:
            if grumpy[i - minutes] == 1:
                window -= customers[i - minutes]
        if window > extra:
            extra = window
    return base + extra

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
    assert max_satisfied([1, 0, 1, 2, 1, 1, 7, 5], [0, 1, 0, 1, 0, 1, 0, 1], 3) == 16
    assert max_satisfied([1], [0], 1) == 1
    assert max_satisfied([1], [1], 1) == 1
    assert max_satisfied([4, 10, 10], [1, 1, 0], 2) == 24
    assert max_satisfied([], [], 1) == 0
    assert stdlib_only()
    print("slide_21 OK")


if __name__ == "__main__":
    main()
