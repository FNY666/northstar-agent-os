"""lis-05: Longest strictly decreasing subsequence.

Negate values and reuse the increasing patience method.

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import bisect
import sys
LIS_05_VERSION = "lis-05.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def lds_length(seq):
    """Length of the longest strictly decreasing subsequence."""
    a = _check_seq(seq)
    tails = []
    for x in a:
        nx = -x
        i = bisect.bisect_left(tails, nx)
        if i == len(tails):
            tails.append(nx)
        else:
            tails[i] = nx
    return len(tails)

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
    assert lds_length([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lds_length([1, 2, 3]) == 1
    assert lds_length([]) == 0
    assert stdlib_only()
    print("lis-05 OK")


if __name__ == "__main__":
    main()
