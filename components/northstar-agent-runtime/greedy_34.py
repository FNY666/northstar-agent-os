"""greedy_34: Advantage shuffle.

For each opponent card (strongest first), sacrifice the smallest card that still beats it.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_34_VERSION = "greedy-34.v1"


def advantage_shuffle(nums1, nums2):
    """Return a permutation of nums1 maximizing positions where it beats nums2."""
    import bisect
    order = sorted(range(len(nums2)), key=lambda i: nums2[i], reverse=True)
    rest = sorted(nums1)
    ans = [0] * len(nums1)
    for i in order:
        j = bisect.bisect_right(rest, nums2[i])
        if j < len(rest):
            ans[i] = rest.pop(j)
        else:
            ans[i] = rest.pop(0)
    return ans

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
    r = advantage_shuffle([2, 7, 11, 15], [1, 10, 4, 11])
    assert sorted(r) == [2, 7, 11, 15]
    assert sum(1 for a, b in zip(r, [1, 10, 4, 11]) if a > b) == 4
    assert advantage_shuffle([12, 24, 8, 32], [13, 25, 32, 11]) == [24, 32, 8, 12]
    assert advantage_shuffle([5], [5]) == [5]
    assert stdlib_only()
    print("greedy_34 OK")


if __name__ == "__main__":
    main()
