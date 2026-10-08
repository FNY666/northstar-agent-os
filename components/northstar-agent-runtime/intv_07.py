"""intv_07: Summarize sorted numbers as ranges (summary_ranges).

Scan for consecutive runs and format them as 'a->b' or 'a'.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_07 = "intv-07.v1"


def summary_ranges(nums):
    """Summarize sorted unique ints as compact ranges."""
    if not nums:
        return []
    res = []
    start = prev = nums[0]
    for x in nums[1:]:
        if x == prev + 1:
            prev = x
        else:
            res.append(str(start) if start == prev else "%d->%d" % (start, prev))
            start = prev = x
    res.append(str(start) if start == prev else "%d->%d" % (start, prev))
    return res

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
    assert summary_ranges([0, 1, 2, 4, 5, 7]) == ["0->2", "4->5", "7"]
    assert summary_ranges([0, 2, 3, 4, 6, 8, 9]) == ["0", "2->4", "6", "8->9"]
    assert summary_ranges([]) == []
    assert summary_ranges([5]) == ["5"]
    assert summary_ranges([-1, 0, 1]) == ["-1->1"]
    assert stdlib_only()
    print("intv_07 OK")


if __name__ == "__main__":
    main()
