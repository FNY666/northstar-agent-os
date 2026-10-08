"""greedy_26: Largest number arrangement.

Sort by the comparator a+b vs b+a so concatenation is maximized.

Time complexity: O(n log n * m) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_26_VERSION = "greedy-26.v1"


def largest_number(nums):
    """Arrange numbers to form the largest possible concatenated number."""
    from functools import cmp_to_key

    def cmp(a, b):
        if a + b > b + a:
            return -1
        if a + b < b + a:
            return 1
        return 0

    strs = [str(x) for x in nums]
    strs.sort(key=cmp_to_key(cmp))
    return "".join(strs).lstrip("0") or "0"

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
    assert largest_number([10, 2]) == "210"
    assert largest_number([3, 30, 34, 5, 9]) == "9534330"
    assert largest_number([0, 0]) == "0"
    assert largest_number([1]) == "1"
    assert stdlib_only()
    print("greedy_26 OK")


if __name__ == "__main__":
    main()
