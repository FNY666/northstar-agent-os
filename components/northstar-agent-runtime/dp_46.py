"""dp-46: Ugly number II.

n-th ugly number (prime factors only 2, 3, 5). Three pointers merge the multiples in order.

Time complexity: O(n) time
Space complexity: O(n) space
"""

import ast
import sys

DP_46_VERSION = "dp-46.v1"


def nth_ugly(n: int) -> int:
    """Return the n-th ugly number (1-indexed)."""
    if n <= 0:
        raise ValueError("n must be positive")
    ugly = [1] * n
    i2 = i3 = i5 = 0
    for i in range(1, n):
        nxt = min(ugly[i2] * 2, ugly[i3] * 3, ugly[i5] * 5)
        ugly[i] = nxt
        if nxt == ugly[i2] * 2:
            i2 += 1
        if nxt == ugly[i3] * 3:
            i3 += 1
        if nxt == ugly[i5] * 5:
            i5 += 1
    return ugly[n - 1]


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
    assert nth_ugly(1) == 1
    assert nth_ugly(10) == 12
    assert nth_ugly(11) == 15
    assert nth_ugly(2) == 2
    assert nth_ugly(7) == 8
    try:
        nth_ugly(0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dp-46 OK")


if __name__ == "__main__":
    main()
