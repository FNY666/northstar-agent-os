"""greedy_27: Split array into consecutive subsequences.

Greedily extend existing tails before starting new length-3 sequences.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_27_VERSION = "greedy-27.v1"


def can_split_consecutive(nums):
    """Return True if nums splits into consecutive subsequences of length >= 3."""
    from collections import Counter
    counts = Counter(nums)
    tails = Counter()
    for x in sorted(nums):
        if counts[x] == 0:
            continue
        counts[x] -= 1
        if tails[x - 1] > 0:
            tails[x - 1] -= 1
            tails[x] += 1
        elif counts[x + 1] > 0 and counts[x + 2] > 0:
            counts[x + 1] -= 1
            counts[x + 2] -= 1
            tails[x + 2] += 1
        else:
            return False
    return True

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
    assert can_split_consecutive([1, 2, 3, 3, 4, 5]) is True
    assert can_split_consecutive([1, 2, 3, 3, 4, 4, 5, 5]) is True
    assert can_split_consecutive([1, 2, 3, 4, 4, 5]) is False
    assert can_split_consecutive([]) is True
    assert stdlib_only()
    print("greedy_27 OK")


if __name__ == "__main__":
    main()
