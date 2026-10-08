"""slide_15: Sliding window maximum.

Fixed-size window with a monotonic decreasing deque of indices: the front always holds the current window maximum.

Time complexity: O(n) time
Space complexity: O(k) auxiliary
"""

import ast
import sys
SLIDE_15_VERSION = "slide-15.v1"


def sliding_window_max(nums, k):
    """Maximum of every window of size k (monotonic deque)."""
    n = len(nums)
    if n == 0 or k <= 0:
        return []
    if k > n:
        k = n
    dq = []
    head = 0
    out = []
    for i, v in enumerate(nums):
        while len(dq) > head and nums[dq[-1]] <= v:
            dq.pop()
        dq.append(i)
        if dq[head] <= i - k:
            head += 1
        if i >= k - 1:
            out.append(nums[dq[head]])
    return out

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
    assert sliding_window_max([1, 3, -1, -3, 5, 3, 6, 7], 3) == [3, 3, 5, 5, 6, 7]
    assert sliding_window_max([1], 1) == [1]
    assert sliding_window_max([9, 8, 7], 2) == [9, 8]
    assert sliding_window_max([1, 2, 3], 3) == [3]
    assert sliding_window_max([], 2) == []
    assert stdlib_only()
    print("slide_15 OK")


if __name__ == "__main__":
    main()
