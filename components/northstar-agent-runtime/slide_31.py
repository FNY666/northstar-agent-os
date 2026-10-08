"""slide_31: K-radius subarray averages.

Fixed-size window of radius k: the average is defined only where the full window fits, otherwise -1.

Time complexity: O(n) time
Space complexity: O(n) output
"""

import ast
import sys
SLIDE_31_VERSION = "slide-31.v1"


def k_radius_averages(nums, k):
    """Averages over radius-k windows; -1 where the window is incomplete."""
    n = len(nums)
    out = [-1] * n
    if k == 0:
        return list(nums)
    size = 2 * k + 1
    if size > n:
        return out
    window = sum(nums[:size])
    for i in range(k, n - k):
        out[i] = window // size
        if i + k + 1 < n:
            window += nums[i + k + 1] - nums[i - k]
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
    assert k_radius_averages([7, 4, 3, 9, 1, 8, 5, 2, 6], 3) == [-1, -1, -1, 5, 4, 4, -1, -1, -1]
    assert k_radius_averages([100000], 0) == [100000]
    assert k_radius_averages([2, 2, 2], 1) == [-1, 2, -1]
    assert k_radius_averages([1, 2], 1) == [-1, -1]
    assert stdlib_only()
    print("slide_31 OK")


if __name__ == "__main__":
    main()
