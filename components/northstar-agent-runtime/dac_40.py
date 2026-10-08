"""dac-40: Stable partition.

Partition each half, then concatenate (matches, rest): order preserved throughout.
"""
import ast
import sys

DAC_40_VERSION = "dac-40.v1"

def _sp(a, pred, lo, hi):
    if lo > hi:
        return [], []
    if lo == hi:
        return ([a[lo]], []) if pred(a[lo]) else ([], [a[lo]])
    mid = (lo + hi) // 2
    t1, f1 = _sp(a, pred, lo, mid)
    t2, f2 = _sp(a, pred, mid + 1, hi)
    return t1 + t2, f1 + f2


def stable_partition(a, pred):
    """Stable partition into (matching, rest), order preserved, via D&C."""
    a = list(a)
    if not a:
        return [], []
    return _sp(a, pred, 0, len(a) - 1)

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
    assert stable_partition([], lambda x: True) == ([], [])
    assert stable_partition([1, 2, 3, 4], lambda x: x % 2 == 0) == ([2, 4], [1, 3])
    t, f = stable_partition([3, 1, 4, 1, 5], lambda x: x > 2)
    assert t == [3, 4, 5] and f == [1, 1]
    assert stable_partition([1, 3], lambda x: x % 2 == 0) == ([], [1, 3])
    assert stdlib_only()
    print("dac-40 OK")


if __name__ == "__main__":
    main()
