"""cc-44: Formability beyond the Frobenius number.

For two coprime denominations every amount above a*b-a-b is formable; smaller amounts are checked with DP.

Time complexity: O(a*b) time worst case
Space complexity: O(a*b)
"""

import ast
import sys

import math

CC_44_VERSION = "cc-44.v1"


def _frobenius(a, b):
    if a <= 0 or b <= 0:
        raise ValueError("denominations must be positive")
    if math.gcd(a, b) != 1:
        raise ValueError("denominations must be coprime")
    return a * b - a - b


def _can_form(amount, denoms):
    reachable = [False] * (amount + 1)
    reachable[0] = True
    for i in range(1, amount + 1):
        for d in denoms:
            if d <= i and reachable[i - d]:
                reachable[i] = True
                break
    return reachable[amount]


def is_formable_beyond_frobenius(a: int, b: int, amount: int) -> bool:
    """True when amount is formable with coprime a, b."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if amount == 0:
        return True
    if _frobenius(a, b) < amount:
        return True
    return _can_form(amount, (a, b))

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
    assert is_formable_beyond_frobenius(3, 5, 100) is True
    assert is_formable_beyond_frobenius(3, 5, 7) is False
    assert is_formable_beyond_frobenius(3, 5, 8) is True
    assert stdlib_only()
    print("cc-44 OK")


if __name__ == "__main__":
    main()
