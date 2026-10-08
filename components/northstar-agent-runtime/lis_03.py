"""lis-03: O(n log n) LIS reconstruction.

Patience sorting that also records predecessors to rebuild one LIS.

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import bisect
import sys
LIS_03_VERSION = "lis-03.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def lis_subsequence(seq):
    """Return one longest strictly increasing subsequence."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return []
    tails = []
    tails_idx = []
    prev = [-1] * n
    for i, x in enumerate(a):
        j = bisect.bisect_left(tails, x)
        if j > 0:
            prev[i] = tails_idx[j - 1]
        if j == len(tails):
            tails.append(x)
            tails_idx.append(i)
        else:
            tails[j] = x
            tails_idx[j] = i
    out = []
    k = tails_idx[-1]
    while k != -1:
        out.append(a[k])
        k = prev[k]
    return out[::-1]

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
    r = lis_subsequence([10, 9, 2, 5, 3, 7, 101, 18])
    assert len(r) == 4 and all(r[i] < r[i + 1] for i in range(3))
    assert lis_subsequence([]) == []
    assert lis_subsequence([5]) == [5]
    assert stdlib_only()
    print("lis-03 OK")


if __name__ == "__main__":
    main()
