"""dac-50: Natural merge sort.

Detect existing sorted runs, then merge runs pairwise divide-and-conquer. O(n log r) runs.
"""
import ast
import sys

DAC_50_VERSION = "dac-50.v1"

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


def _runs(a):
    if not a:
        return []
    runs = []
    start = 0
    for i in range(1, len(a)):
        if a[i] < a[i - 1]:
            runs.append(a[start:i])
            start = i
    runs.append(a[start:])
    return runs


def _merge_all(runs):
    if len(runs) <= 1:
        return runs[0] if runs else []
    mid = len(runs) // 2
    return _merge2(_merge_all(runs[:mid]), _merge_all(runs[mid:]))


def natural_merge_sort(a):
    """Natural merge sort: detect runs, merge them divide-and-conquer."""
    return _merge_all(_runs(list(a)))

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
    assert natural_merge_sort([]) == []
    assert natural_merge_sort([1, 2, 3, 4]) == [1, 2, 3, 4]
    assert natural_merge_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert natural_merge_sort([1, 3, 2, 4, 6, 5]) == [1, 2, 3, 4, 5, 6]
    assert natural_merge_sort([2, 2, 1, 1]) == [1, 1, 2, 2]
    assert stdlib_only()
    print("dac-50 OK")


if __name__ == "__main__":
    main()
