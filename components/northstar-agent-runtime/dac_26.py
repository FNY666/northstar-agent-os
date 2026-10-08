"""dac-26: Majority element (divide and conquer).

Majority of the whole array must be the majority of some half; merge candidates by recount.
"""
import ast
import sys

DAC_26_VERSION = "dac-26.v1"

def _count(a, x, lo, hi):
    return sum(1 for i in range(lo, hi + 1) if a[i] == x)


def _maj(a, lo, hi):
    if lo == hi:
        return a[lo]
    mid = (lo + hi) // 2
    left = _maj(a, lo, mid)
    right = _maj(a, mid + 1, hi)
    if left == right:
        return left
    return left if _count(a, left, lo, hi) > _count(a, right, lo, hi) else right


def majority_element(a):
    """Majority candidate via divide and conquer (verify with a count)."""
    if not a:
        raise ValueError("empty")
    return _maj(list(a), 0, len(a) - 1)

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
    assert majority_element([3, 2, 3]) == 3
    assert majority_element([2, 2, 1, 1, 1, 2, 2]) == 2
    assert majority_element([1]) == 1
    cand = majority_element([1, 1, 2, 1, 3, 1, 1])
    assert [1, 1, 2, 1, 3, 1, 1].count(cand) > 7 // 2
    try:
        majority_element([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-26 OK")


if __name__ == "__main__":
    main()
