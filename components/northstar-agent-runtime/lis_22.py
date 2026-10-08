"""lis-22: LIS via segment tree.

Range-max segment tree over compressed coordinates.

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import sys
LIS_22_VERSION = "lis-22.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def lis_segtree(seq):
    """LIS length using an iterative segment tree for range maxima."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return 0
    vals = sorted(set(a))
    rank = {v: i for i, v in enumerate(vals)}
    m = len(vals)
    size = 1
    while size < m:
        size *= 2
    tree = [0] * (2 * size)

    def seg_update(p, v):
        p += size
        if v <= tree[p]:
            return
        tree[p] = v
        p //= 2
        while p:
            left = tree[2 * p]
            right = tree[2 * p + 1]
            tree[p] = left if left > right else right
            p //= 2

    def seg_query(l, r):
        res = 0
        l += size
        r += size
        while l < r:
            if l & 1:
                if tree[l] > res:
                    res = tree[l]
                l += 1
            if r & 1:
                r -= 1
                if tree[r] > res:
                    res = tree[r]
            l //= 2
            r //= 2
        return res

    for x in a:
        r = rank[x]
        seg_update(r, seg_query(0, r) + 1)
    return seg_query(0, m)

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
    assert lis_segtree([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis_segtree([5, 4, 3, 2, 1]) == 1
    assert lis_segtree([]) == 0
    assert stdlib_only()
    print("lis-22 OK")


if __name__ == "__main__":
    main()
