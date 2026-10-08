"""greedy_15: Lemonade change.

Prefer spending a ten plus a five over three fives when giving $15 change.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_15_VERSION = "greedy-15.v1"


def lemonade_change(bills):
    """Return True if every customer can be served with correct change."""
    five = 0
    ten = 0
    for b in bills:
        if b == 5:
            five += 1
        elif b == 10:
            if five == 0:
                return False
            five -= 1
            ten += 1
        elif b == 20:
            if ten > 0 and five > 0:
                ten -= 1
                five -= 1
            elif five >= 3:
                five -= 3
            else:
                return False
        else:
            raise ValueError("unexpected bill: %r" % b)
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
    assert lemonade_change([5, 5, 5, 10, 20]) is True
    assert lemonade_change([5, 5, 10, 10, 20]) is False
    assert lemonade_change([]) is True
    assert lemonade_change([10]) is False
    assert stdlib_only()
    print("greedy_15 OK")


if __name__ == "__main__":
    main()
