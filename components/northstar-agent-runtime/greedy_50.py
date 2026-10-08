"""greedy_50: Maximum 69 number.

Change the leftmost 6 to 9; that single greedy choice is optimal.

Time complexity: O(d) time
Space complexity: O(d) auxiliary
"""

import ast
import sys
GREEDY_50_VERSION = "greedy-50.v1"


def maximum_69_number(num):
    """Return the maximum number after changing at most one 6 to 9."""
    return int(str(num).replace("6", "9", 1))

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
    assert maximum_69_number(9669) == 9969
    assert maximum_69_number(9996) == 9999
    assert maximum_69_number(9999) == 9999
    assert maximum_69_number(6) == 9
    assert stdlib_only()
    print("greedy_50 OK")


if __name__ == "__main__":
    main()
