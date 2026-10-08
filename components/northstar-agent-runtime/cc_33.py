"""cc-33: Subset-sum feasibility.

Can a subset of the given values sum exactly to target (0/1).

Time complexity: O(target * num_values) time
Space complexity: O(target)
"""

import ast
import sys

CC_33_VERSION = "cc-33.v1"


def subset_sum(values: list, target: int) -> bool:
    """True when some subset of values sums to target."""
    if target < 0:
        raise ValueError("target must be non-negative")
    if any(v <= 0 for v in values):
        raise ValueError("values must be positive")
    reachable = {0}
    for v in values:
        reachable |= {x + v for x in reachable if x + v <= target}
    return target in reachable

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
    assert subset_sum([1, 2, 5, 10], 8) is True
    assert subset_sum([1, 2, 5, 10], 9) is False
    assert subset_sum([3], 0) is True
    assert stdlib_only()
    print("cc-33 OK")


if __name__ == "__main__":
    main()
