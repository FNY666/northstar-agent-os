"""bs_49: Sparse array search

Binary search in a sorted array interspersed with empty
strings, skipping blanks around the midpoint.

Time complexity: O(log n) average, O(n) worst case
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_49_VERSION = "bs-49.v1"


def sparse_search(a, target):
    """Search target in a sorted sparse string array; -1 when absent."""
    lo, hi = 0, len(a) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == "":
            l, r = mid - 1, mid + 1
            while True:
                if l < lo and r > hi:
                    return -1
                if r <= hi and a[r] != "":
                    mid = r
                    break
                if l >= lo and a[l] != "":
                    mid = l
                    break
                l -= 1
                r += 1
        if a[mid] == target:
            return mid
        if a[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1

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
    a = ["at", "", "", "", "ball", "", "", "car", "", "", "dad", "", ""]
    assert sparse_search(a, "ball") == 4
    assert sparse_search(a, "at") == 0
    assert sparse_search(a, "dad") == 10
    assert sparse_search(a, "x") == -1
    assert sparse_search(["", ""], "a") == -1
    assert sparse_search(["a"], "a") == 0
    assert stdlib_only()
    print("bs_49 OK")


if __name__ == "__main__":
    main()
