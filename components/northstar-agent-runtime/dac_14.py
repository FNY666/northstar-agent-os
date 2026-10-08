"""dac-14: Median of medians (deterministic select).

Guaranteed O(n) selection: pivot is the median of group medians, recurse on one side.
"""
import ast
import sys

DAC_14_VERSION = "dac-14.v1"

def _select(a, k):
    if len(a) <= 5:
        return sorted(a)[k]
    groups = [sorted(a[i:i + 5]) for i in range(0, len(a), 5)]
    medians = [g[len(g) // 2] for g in groups]
    pivot = _select(medians, len(medians) // 2)
    low = [x for x in a if x < pivot]
    high = [x for x in a if x > pivot]
    eq = len(a) - len(low) - len(high)
    if k < len(low):
        return _select(low, k)
    if k < len(low) + eq:
        return pivot
    return _select(high, k - len(low) - eq)


def median_of_medians(a, k):
    """Deterministic linear-time k-th smallest (0-based)."""
    a = list(a)
    if not 0 <= k < len(a):
        raise ValueError("k out of range")
    return _select(a, k)

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
    assert median_of_medians([3, 1, 2], 1) == 2
    assert median_of_medians(list(range(100, 0, -1)), 0) == 1
    assert median_of_medians(list(range(100, 0, -1)), 99) == 100
    assert median_of_medians([9, 1, 8, 2, 7, 3], 2) == 3
    try:
        median_of_medians([], 0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-14 OK")


if __name__ == "__main__":
    main()
