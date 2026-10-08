"""cc-43: Frobenius number (two coprime denominations).

Largest amount not formable with two coprime denominations: a*b - a - b (Chicken McNugget theorem).

Time complexity: O(log min(a,b)) time
Space complexity: O(1)
"""

import ast
import sys

import math

CC_43_VERSION = "cc-43.v1"


def frobenius_two(a: int, b: int) -> int:
    """Largest unformable amount for coprime a, b: a*b - a - b."""
    if a <= 0 or b <= 0:
        raise ValueError("denominations must be positive")
    if math.gcd(a, b) != 1:
        raise ValueError("denominations must be coprime")
    return a * b - a - b

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
    assert frobenius_two(3, 5) == 7
    assert frobenius_two(4, 7) == 17
    try:
        frobenius_two(4, 6)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("cc-43 OK")


if __name__ == "__main__":
    main()
