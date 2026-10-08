"""lis-09: Russian doll envelopes (2D nesting).

Sort by width asc / height desc, then 1D LIS on heights.

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import bisect
import sys
LIS_09_VERSION = "lis-09.v1"


def _check_pairs(pairs):
    """Validate pairs is a list/tuple of 2-number pairs; return list of [w, h]."""
    if not isinstance(pairs, (list, tuple)):
        raise ValueError("pairs must be a list or tuple")
    out = []
    for p in pairs:
        if not isinstance(p, (list, tuple)) or len(p) != 2:
            raise ValueError("each pair must have length 2")
        w, h = p
        if not isinstance(w, (int, float)) or not isinstance(h, (int, float)):
            raise ValueError("pair elements must be numbers")
        out.append([w, h])
    return out
def max_nested_envelopes(pairs):
    """Max number of envelopes nested strictly inside one another."""
    pts = _check_pairs(pairs)
    pts.sort(key=lambda p: (p[0], -p[1]))
    tails = []
    for _, h in pts:
        i = bisect.bisect_left(tails, h)
        if i == len(tails):
            tails.append(h)
        else:
            tails[i] = h
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
    assert max_nested_envelopes([[5, 4], [6, 4], [6, 7], [2, 3]]) == 3
    assert max_nested_envelopes([]) == 0
    assert max_nested_envelopes([[1, 1], [1, 1], [1, 1]]) == 1
    assert stdlib_only()
    print("lis-09 OK")


if __name__ == "__main__":
    main()
