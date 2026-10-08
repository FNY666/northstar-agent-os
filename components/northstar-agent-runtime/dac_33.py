"""dac-33: Quicksort (iterative, explicit stack).

Same divide-and-conquer partitioning, but subproblems go on a stack: no recursion depth risk.
"""
import ast
import sys

DAC_33_VERSION = "dac-33.v1"

def quick_sort_iterative(a):
    """Quicksort with an explicit stack; returns a sorted copy."""
    a = list(a)
    stack = [(0, len(a) - 1)]
    while stack:
        lo, hi = stack.pop()
        if lo >= hi:
            continue
        pivot = a[(lo + hi) // 2]
        i, j = lo, hi
        while i <= j:
            while a[i] < pivot:
                i += 1
            while a[j] > pivot:
                j -= 1
            if i <= j:
                a[i], a[j] = a[j], a[i]
                i += 1
                j -= 1
        stack.append((lo, j))
        stack.append((i, hi))
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
    assert quick_sort_iterative([]) == []
    assert quick_sort_iterative([3, 1, 2]) == [1, 2, 3]
    assert quick_sort_iterative(list(range(200, 0, -1))) == list(range(1, 201))
    assert quick_sort_iterative([4, 4, 1, 4]) == [1, 4, 4, 4]
    assert stdlib_only()
    print("dac-33 OK")


if __name__ == "__main__":
    main()
