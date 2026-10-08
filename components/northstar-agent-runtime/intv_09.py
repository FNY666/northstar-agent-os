"""intv_09: Partition string into max parts by last occurrence (partition_labels).

Track the last index of each char; cut when the scan passes the running max.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_09 = "intv-09.v1"


def partition_labels(s):
    """Return sizes of maximal partitions with disjoint character sets."""
    last = {}
    for i, ch in enumerate(s):
        last[ch] = i
    res = []
    start = end = 0
    for i, ch in enumerate(s):
        if last[ch] > end:
            end = last[ch]
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
    assert partition_labels("abc") == [1, 1, 1]
    assert partition_labels("aaaa") == [4]
    assert partition_labels("") == []
    assert stdlib_only()
    print("intv_09 OK")


if __name__ == "__main__":
    main()
