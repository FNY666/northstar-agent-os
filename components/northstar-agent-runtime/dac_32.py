"""dac-32: Segment tree (range minimum query).

Build a tournament tree bottom-up; each query splits the range divide-and-conquer. O(log n).
"""
import ast
import sys

DAC_32_VERSION = "dac-32.v1"

def build_rmq(a):
    """Build a segment tree for range-min; returns (tree, size)."""
    n = len(a)
    size = 1
    while size < n:
        size *= 2
    tree = [float("inf")] * (2 * size)
    for i, v in enumerate(a):
        tree[size + i] = v
    for i in range(size - 1, 0, -1):
        tree[i] = tree[2 * i] if tree[2 * i] < tree[2 * i + 1] else tree[2 * i + 1]
    return tree, size


def range_min(tree, size, l, r):
    """Minimum on [l, r) via segment-tree divide and conquer."""
    l += size
    r += size
    best = float("inf")
    while l < r:
        if l % 2:
            if tree[l] < best:
                best = tree[l]
            l += 1
        if r % 2:
            r -= 1
            if tree[r] < best:
                best = tree[r]
        l //= 2
        r //= 2
    return best

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
    t, s = build_rmq([5, 2, 8, 1, 9])
    assert range_min(t, s, 0, 5) == 1
    assert range_min(t, s, 0, 2) == 2
    assert range_min(t, s, 2, 4) == 1
    assert range_min(t, s, 3, 4) == 1
    assert range_min(t, s, 4, 5) == 9
    assert stdlib_only()
    print("dac-32 OK")


if __name__ == "__main__":
    main()
