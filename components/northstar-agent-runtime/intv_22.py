"""intv_22: Merge bold ranges for add-bold-tag (bold_ranges).

Find all matches of each word, merge overlapping ranges.

Time complexity: O(n * m) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_22 = "intv-22.v1"


def bold_ranges(s, words):
    """Return merged [start, end) ranges to bold in ``s``."""
    hits = []
    for w in words:
        start = 0
        while True:
            i = s.find(w, start)
            if i < 0:
                break
            hits.append((i, i + len(w)))
            start = i + 1
    if not hits:
        return []
    hits.sort()
    merged = [list(hits[0])]
    for a, b in hits[1:]:
        if a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return [tuple(m) for m in merged]

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
    assert bold_ranges("abcxyz123", ["abc", "123"]) == [(0, 3), (6, 9)]
    assert bold_ranges("aaabbcc", ["aaa", "aab", "bc"]) == [(0, 6)]
    assert bold_ranges("hello", ["zz"]) == []
    assert bold_ranges("abc", ["b"]) == [(1, 2)]
    assert bold_ranges("aaaa", ["aa"]) == [(0, 4)]
    assert stdlib_only()
    print("intv_22 OK")


if __name__ == "__main__":
    main()
