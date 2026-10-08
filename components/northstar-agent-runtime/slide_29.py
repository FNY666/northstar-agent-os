"""slide_29: Shortest subarray with sum at least k.

Prefix sums with a monotonic increasing deque of indices: pop from the front whenever a qualifying subarray is found.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
SLIDE_29_VERSION = "slide-29.v1"


def shortest_subarray_sum_k(nums, k):
    """Shortest subarray with sum >= k (handles negatives)."""
    n = len(nums)
    prefix = [0] * (n + 1)
    for i, v in enumerate(nums):
        prefix[i + 1] = prefix[i] + v
    dq = []
    head = 0
    best = n + 1
    for i, p in enumerate(prefix):
        while len(dq) > head and p - prefix[dq[head]] >= k:
            if i - dq[head] < best:
                best = i - dq[head]
            head += 1
        while dq and prefix[dq[-1]] >= p:
            dq.pop()
        dq.append(i)
    return -1 if best == n + 1 else best

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
    assert shortest_subarray_sum_k([1], 1) == 1
    assert shortest_subarray_sum_k([1, 2], 4) == -1
    assert shortest_subarray_sum_k([2, -1, 2], 3) == 3
    assert shortest_subarray_sum_k([84, -37, 32, 40, 95], 167) == 3
    assert shortest_subarray_sum_k([1, 2, 3], 6) == 3
    assert stdlib_only()
    print("slide_29 OK")


if __name__ == "__main__":
    main()
