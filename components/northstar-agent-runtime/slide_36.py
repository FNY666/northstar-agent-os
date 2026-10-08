"""slide_36: Longest even-odd subarray with threshold.

Variable window: reset the left edge on values above the threshold or when two adjacent values share the same parity.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_36_VERSION = "slide-36.v1"


def longest_even_odd(nums, threshold):
    """Longest even-odd alternating subarray with values <= threshold."""
    best = 0
    left = 0
    for right, v in enumerate(nums):
        if v > threshold:
            left = right + 1
            continue
        if right > left and (nums[right] % 2) == (nums[right - 1] % 2):
            left = right
        if right - left + 1 > best:
            best = right - left + 1
    return best

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
    assert longest_even_odd([3, 2, 5, 4], 5) == 4
    assert longest_even_odd([1, 2], 3) == 2
    assert longest_even_odd([2, 3, 10, 2], 10) == 3
    assert longest_even_odd([10, 11], 10) == 1
    assert longest_even_odd([2], 5) == 1
    assert stdlib_only()
    print("slide_36 OK")


if __name__ == "__main__":
    main()
