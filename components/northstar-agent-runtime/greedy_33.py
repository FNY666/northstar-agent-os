"""greedy_33: Patching array.

Maintain the reachable range [1, miss); patch by doubling miss when the next number is too big.

Time complexity: O(n + log N) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_33_VERSION = "greedy-33.v1"


def min_patches(nums, n):
    """Return the minimum patches so every number in [1, n] is representable."""
    patches = 0
    miss = 1
    i = 0
    while miss <= n:
        if i < len(nums) and nums[i] <= miss:
            miss += nums[i]
            i += 1
        else:
            miss += miss
            patches += 1
    return patches

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
    assert min_patches([1, 3], 6) == 1
    assert min_patches([1, 5, 10], 20) == 2
    assert min_patches([1, 2, 2], 5) == 0
    assert min_patches([], 7) == 3
    assert stdlib_only()
    print("greedy_33 OK")


if __name__ == "__main__":
    main()
