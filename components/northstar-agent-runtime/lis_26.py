"""lis-26: Longest strictly increasing contiguous run.

Single pass over adjacent pairs; the contiguous cousin of LIS.

Time complexity: O(n) time
Space complexity: O(1)"""

import ast
import sys
LIS_26_VERSION = "lis-26.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def longest_increasing_run(seq):
    """Length of the longest strictly increasing contiguous run."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return 0
    best = cur = 1
    for i in range(1, n):
        if a[i] > a[i - 1]:
            cur += 1
        else:
            if cur > best:
                best = cur
            cur = 1
    return best if best > cur else cur

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
    assert longest_increasing_run([1, 3, 5, 4, 7]) == 3
    assert longest_increasing_run([1, 2, 3, 4]) == 4
    assert longest_increasing_run([]) == 0
    assert stdlib_only()
    print("lis-26 OK")


if __name__ == "__main__":
    main()
