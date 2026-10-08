"""cc-15: Exact-k coins reconstruction.

Find coins summing to amount using exactly k coins; returns the sorted coin list or None when impossible.

Time complexity: O(amount * k * num_denominations) time
Space complexity: O(amount * k)
"""

import ast
import sys

CC_15_VERSION = "cc-15.v1"


def coins_with_exact_k(amount: int, coins: list, k: int):
    """Coin list of length k summing to amount, or None."""
    if amount < 0 or k < 0:
        raise ValueError("amount and k must be non-negative")
    denoms = sorted(set(coins))
    if any(d <= 0 for d in denoms):
        raise ValueError("denominations must be positive")
    reach = [[False] * (k + 1) for _ in range(amount + 1)]
    prev = [[None] * (k + 1) for _ in range(amount + 1)]
    reach[0][0] = True
    for i in range(amount + 1):
        for j in range(k):
            if reach[i][j]:
                for d in denoms:
                    ni = i + d
                    if ni <= amount and not reach[ni][j + 1]:
                        reach[ni][j + 1] = True
                        prev[ni][j + 1] = (i, d)
    if not reach[amount][k]:
        return None
    out = []
    ci, cj = amount, k
    while cj > 0:
        pi, d = prev[ci][cj]
        out.append(d)
        ci, cj = pi, cj - 1
    return sorted(out)

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
    assert coins_with_exact_k(11, [1, 2, 5], 3) == [1, 5, 5]
    assert coins_with_exact_k(11, [1, 2, 5], 2) is None
    assert coins_with_exact_k(0, [1], 0) == []
    assert stdlib_only()
    print("cc-15 OK")


if __name__ == "__main__":
    main()
