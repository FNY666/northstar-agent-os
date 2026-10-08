"""dp-02: Climbing stairs.

Count ways to reach step n taking 1 or 2 steps at a time. ways(n) = ways(n-1) + ways(n-2) with ways(0)=ways(1)=1.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

DP_02_VERSION = "dp-02.v1"


def climb_stairs(n: int) -> int:
    """Return the number of distinct ways to climb n steps (1 or 2 at a time)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n <= 1:
        return 1
    a, b = 1, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b


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
    assert climb_stairs(0) == 1
    assert climb_stairs(1) == 1
    assert climb_stairs(2) == 2
    assert climb_stairs(3) == 3
    assert climb_stairs(5) == 8
    assert climb_stairs(10) == 89
    try:
        climb_stairs(-1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-02 OK")


if __name__ == "__main__":
    main()
