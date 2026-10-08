"""slide_32: Number of subarrays of size k with average at least threshold.

Fixed-size window: compare the running sum against threshold * k to avoid floating point division.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_32_VERSION = "slide-32.v1"


def num_k_avg_threshold(arr, k, threshold):
    """Count length-k subarrays with average >= threshold."""
    n = len(arr)
    if n == 0 or k <= 0 or k > n:
        return 0
    need = threshold * k
    window = sum(arr[:k])
    count = 1 if window >= need else 0
    for i in range(k, n):
        window += arr[i] - arr[i - k]
        if window >= need:
            count += 1
    return count

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
    assert num_k_avg_threshold([2, 2, 2, 2, 5, 5, 5, 8], 3, 4) == 3
    assert num_k_avg_threshold([11, 13, 17, 23, 29, 31, 7, 5, 2, 3], 3, 5) == 6
    assert num_k_avg_threshold([4], 1, 5) == 0
    assert num_k_avg_threshold([5], 1, 5) == 1
    assert num_k_avg_threshold([], 1, 1) == 0
    assert stdlib_only()
    print("slide_32 OK")


if __name__ == "__main__":
    main()
