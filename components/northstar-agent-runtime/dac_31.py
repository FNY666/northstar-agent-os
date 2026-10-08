"""dac-31: Parallel prefix sums.

Recursive doubling: prefix each half, then offset the right half by the left total.
"""
import ast
import sys

DAC_31_VERSION = "dac-31.v1"

def prefix_sums_dc(a):
    """Prefix sums via divide and conquer."""
    a = list(a)
    if len(a) <= 1:
        return a
    mid = len(a) // 2
    left = prefix_sums_dc(a[:mid])
    right = prefix_sums_dc(a[mid:])
    s = left[-1]
    return left + [s + x for x in right]

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
    assert prefix_sums_dc([]) == []
    assert prefix_sums_dc([5]) == [5]
    assert prefix_sums_dc([1, 2, 3, 4]) == [1, 3, 6, 10]
    assert prefix_sums_dc([2, -1, 3]) == [2, 1, 4]
    assert prefix_sums_dc([1, 1, 1, 1, 1]) == [1, 2, 3, 4, 5]
    assert stdlib_only()
    print("dac-31 OK")


if __name__ == "__main__":
    main()
