"""cc-21: Minimum coins via BFS.

Shortest-path view: amounts are nodes, adding a coin is an edge; BFS from 0 finds the fewest coins.

Time complexity: O(amount * num_denominations) time
Space complexity: O(amount)
"""

import ast
import sys

from collections import deque

CC_21_VERSION = "cc-21.v1"


def min_coins_bfs(amount: int, coins: list) -> int:
    """Fewest coins via BFS; -1 if impossible."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    if amount == 0:
        return 0
    seen = {0}
    queue = deque([(0, 0)])
    while queue:
        val, steps = queue.popleft()
        for d in denoms:
            nxt = val + d
            if nxt == amount:
                return steps + 1
            if nxt < amount and nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, steps + 1))
    return -1

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
    assert min_coins_bfs(11, [1, 2, 5]) == 3
    assert min_coins_bfs(3, [2]) == -1
    assert min_coins_bfs(0, [1, 2]) == 0
    assert stdlib_only()
    print("cc-21 OK")


if __name__ == "__main__":
    main()
