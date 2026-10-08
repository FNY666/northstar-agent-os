"""slide_17: First negative number in every window of size k.

Fixed-size window with a queue of negative indices: the front holds the first negative of the current window (0 when there is none).

Time complexity: O(n) time
Space complexity: O(k) auxiliary
"""

import ast
import sys
SLIDE_17_VERSION = "slide-17.v1"


def first_negative_k(nums, k):
    """First negative number in every window of size k (0 if none)."""
    n = len(nums)
    if n == 0 or k <= 0 or k > n:
        return []
    neg = []
    out = []
    for i, v in enumerate(nums):
        if v < 0:
            neg.append(i)
        while neg and neg[0] <= i - k:
            neg.pop(0)
        if i >= k - 1:
            out.append(nums[neg[0]] if neg else 0)
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
    assert first_negative_k([12, -1, -7, 8, -15, 30, 16, 28], 3) == [-1, -1, -7, -15, -15, 0]
    assert first_negative_k([1, 2, 3], 2) == [0, 0]
    assert first_negative_k([-5, -1], 1) == [-5, -1]
    assert first_negative_k([1, -2, 3, -4], 2) == [-2, -2, -4]
    assert stdlib_only()
    print("slide_17 OK")


if __name__ == "__main__":
    main()
