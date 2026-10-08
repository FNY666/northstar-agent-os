"""dp-16: Egg drop (minimum moves).

Fewest moves in the worst case to find the critical floor with a given number of eggs. DP over moves: dp[e] floors covered.

Time complexity: O(eggs * moves) time
Space complexity: O(eggs) space
"""

import ast
import sys

DP_16_VERSION = "dp-16.v1"


def egg_drop(eggs: int, floors: int) -> int:
    """Return the minimum worst-case moves to find the critical floor."""
    if eggs <= 0:
        raise ValueError("need at least one egg")
    if floors <= 1:
        return floors
    if eggs == 1:
        return floors
    dp = [0] * (eggs + 1)
    moves = 0
    while dp[eggs] < floors:
        moves += 1
        for e in range(eggs, 0, -1):
            dp[e] = dp[e] + dp[e - 1] + 1
    return moves


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
    assert egg_drop(1, 10) == 10
    assert egg_drop(2, 10) == 4
    assert egg_drop(2, 100) == 14
    assert egg_drop(3, 14) == 4
    assert egg_drop(2, 1) == 1
    assert egg_drop(3, 0) == 0
    try:
        egg_drop(0, 5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-16 OK")


if __name__ == "__main__":
    main()
