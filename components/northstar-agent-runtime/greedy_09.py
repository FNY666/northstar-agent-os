"""greedy_09: Partition labels.

Extend each partition to the last occurrence of every character seen so far.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_09_VERSION = "greedy-09.v1"


def partition_labels(s):
    """Return the sizes of maximal partitions with disjoint character sets."""
    last = {}
    for i, c in enumerate(s):
        last[c] = i
    res = []
    start = 0
    end = 0
    for i, c in enumerate(s):
        end = max(end, last[c])
        if i == end:
            res.append(end - start + 1)
            start = i + 1
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
    assert partition_labels("ababcbacadefegdehijhklij") == [9, 7, 8]
    assert partition_labels("eccbbbbdec") == [10]
    assert partition_labels("") == []
    assert partition_labels("a") == [1]
    assert stdlib_only()
    print("greedy_09 OK")


if __name__ == "__main__":
    main()
