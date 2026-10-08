"""cc-48: Largest unformable amount.

Largest amount that cannot be formed (Chicken McNugget generalization); -1 when 1 is a denomination.

Time complexity: O(bound * num_denominations) time
Space complexity: O(bound)
"""

import ast
import sys

import math

CC_48_VERSION = "cc-48.v1"


def largest_unformable(coins: list, bound: int = None) -> int:
    """Largest unformable amount; -1 if every amount is formable."""
    denoms = sorted(set(coins))
    if not denoms:
        raise ValueError("coins must be non-empty")
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if 1 in denoms:
        return -1
    if math.gcd(*denoms) != 1:
        raise ValueError("gcd of denominations must be 1")
    if bound is None:
        bound = max(denoms) * max(denoms)
    reachable = [False] * (bound + 1)
    reachable[0] = True
    for i in range(1, bound + 1):
        for d in denoms:
            if d > i:
                break
            if reachable[i - d]:
                reachable[i] = True
                break
    t = bound
    while t >= 0 and reachable[t]:
        t -= 1
    if any(not reachable[i] for i in range(t + 1, bound + 1)):
        raise ValueError("bound too small; increase bound")
    return t

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
    assert largest_unformable([3, 5]) == 7
    assert largest_unformable([4, 7]) == 17
    assert largest_unformable([1, 2, 5]) == -1
    assert stdlib_only()
    print("cc-48 OK")


if __name__ == "__main__":
    main()
