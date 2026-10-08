"""dac-15: Merge k sorted lists.

Pairwise divide-and-conquer merging: O(N log k) for N total elements.
"""
import ast
import sys

DAC_15_VERSION = "dac-15.v1"

def _merge2(a, b):
    out = []
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i] <= b[j]:
            out.append(a[i])
            i += 1
        else:
            out.append(b[j])
            j += 1
    out.extend(a[i:])
    out.extend(b[j:])
    return out


def merge_k_sorted(lists):
    """Merge k sorted lists by pairwise divide and conquer."""
    lists = [list(l) for l in lists]
    if not lists:
        return []
    while len(lists) > 1:
        nxt = []
        for i in range(0, len(lists), 2):
            if i + 1 < len(lists):
                nxt.append(_merge2(lists[i], lists[i + 1]))
            else:
                nxt.append(lists[i])
        lists = nxt
    return lists[0]

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
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
    assert merge_k_sorted([]) == []
    assert merge_k_sorted([[1, 4], [2, 5], [3, 6]]) == [1, 2, 3, 4, 5, 6]
    assert merge_k_sorted([[1], [2], [3]]) == [1, 2, 3]
    assert merge_k_sorted([[], [1], []]) == [1]
    assert merge_k_sorted([[5, 9], [1], [3, 4, 8]]) == [1, 3, 4, 5, 8, 9]
    assert stdlib_only()
    print("dac-15 OK")


if __name__ == "__main__":
    main()
