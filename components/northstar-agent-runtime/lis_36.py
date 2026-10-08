"""lis-36: LIS length of each prefix.

Online patience: report the LIS length after each new element.

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import bisect
import sys
LIS_36_VERSION = "lis-36.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def lis_prefix_lengths(seq):
    """LIS length of seq[:i+1] for every prefix."""
    a = _check_seq(seq)
    tails = []
    out = []
    for x in a:
        i = bisect.bisect_left(tails, x)
        if i == len(tails):
            tails.append(x)
        else:
            tails[i] = x
        out.append(len(tails))
    return out

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
    assert lis_prefix_lengths([3, 1, 2]) == [1, 1, 2]
    assert lis_prefix_lengths([1, 2, 3]) == [1, 2, 3]
    assert lis_prefix_lengths([]) == []
    assert stdlib_only()
    print("lis-36 OK")


if __name__ == "__main__":
    main()
