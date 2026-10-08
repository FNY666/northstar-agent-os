"""intv_46: Maximum value attending at most k events (max_value_events).

Sort by start; DP over events with binary search for next compatible.

Time complexity: O(nk log n) time
Space complexity: O(nk) auxiliary
"""

import ast
import sys

import bisect
INTV_46 = "intv-46.v1"


def max_value_events(events, k):
    """Max total value attending at most ``k`` non-overlapping events."""
    events = sorted(events, key=lambda x: x[0])
    starts = [e[0] for e in events]
    n = len(events)
    nxt = [bisect.bisect_right(starts, events[i][1]) for i in range(n)]
    dp = [[0] * (k + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(1, k + 1):
            dp[i][j] = max(dp[i + 1][j], events[i][2] + dp[nxt[i]][j - 1])
    return dp[0][k]

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
    assert max_value_events([[1, 2, 4], [3, 4, 3], [2, 3, 1]], 2) == 7
    assert max_value_events([[1, 2, 4], [3, 4, 3], [2, 3, 10]], 2) == 10
    assert max_value_events([[1, 1, 1], [2, 2, 2], [3, 3, 3], [4, 4, 4]], 3) == 9
    assert max_value_events([[1, 2, 5]], 1) == 5
    assert max_value_events([], 2) == 0
    assert stdlib_only()
    print("intv_46 OK")


if __name__ == "__main__":
    main()
