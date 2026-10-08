"""dac-34: Sort colors (0/1/2, divide and conquer).

Recursively sort halves, then merge; values restricted to {0,1,2}.
"""
import ast
import sys

DAC_34_VERSION = "dac-34.v1"

def _sort3(a, lo, hi):
    if lo >= hi:
        return
    if hi - lo == 1:
        if a[lo] > a[hi]:
            a[lo], a[hi] = a[hi], a[lo]
        return
    mid = (lo + hi) // 2
    _sort3(a, lo, mid)
    _sort3(a, mid + 1, hi)
    tmp = []
    i, j = lo, mid + 1
    while i <= mid and j <= hi:
        if a[i] <= a[j]:
            tmp.append(a[i])
            i += 1
        else:
            tmp.append(a[j])
            j += 1
    while i <= mid:
        tmp.append(a[i])
        i += 1
    while j <= hi:
        tmp.append(a[j])
        j += 1
    a[lo:hi + 1] = tmp


def sort_colors_dc(a):
    """Sort a 0/1/2 array via divide-and-conquer merge."""
    a = list(a)
    _sort3(a, 0, len(a) - 1)
    return a

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
    assert sort_colors_dc([]) == []
    assert sort_colors_dc([2, 0, 2, 1, 1, 0]) == [0, 0, 1, 1, 2, 2]
    assert sort_colors_dc([2, 1, 0]) == [0, 1, 2]
    assert sort_colors_dc([0, 0, 0]) == [0, 0, 0]
    assert stdlib_only()
    print("dac-34 OK")


if __name__ == "__main__":
    main()
