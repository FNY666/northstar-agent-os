"""lis-27: Decision: increasing run of length K (fast).

Patience sorting with early exit once K piles are reached.

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import bisect
import sys
LIS_27_VERSION = "lis-27.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def has_increasing_subseq_len(seq, k):
    """True iff some strictly increasing subsequence has length >= k."""
    a = _check_seq(seq)
    if not isinstance(k, int):
        raise ValueError("k must be an int")
    if k < 0:
        raise ValueError("k must be non-negative")
    if k == 0:
        return True
    tails = []
    for x in a:
        i = bisect.bisect_left(tails, x)
        if i == len(tails):
            tails.append(x)
        else:
            tails[i] = x
        if len(tails) >= k:
            return True
    return False

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
    assert has_increasing_subseq_len([3, 1, 2], 2) is True
    assert has_increasing_subseq_len([3, 1, 2], 3) is False
    assert has_increasing_subseq_len([], 0) is True
    assert stdlib_only()
    print("lis-27 OK")


if __name__ == "__main__":
    main()
